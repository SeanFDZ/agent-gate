# Agent Gate — OPA Policy (auto-generated from policies/default.yaml)
#
# This policy evaluates structured tool call input and returns
# a classification decision with tier, reason, and envelope status.

package agent_gate

import future.keywords.in
import future.keywords.every
import future.keywords.contains
import future.keywords.if

# =========================================================================
# ENVELOPE DATA
# =========================================================================

allowed_paths := {
    "${WORKDIR}/**",
}

denied_paths := {
    "${HOME}/.ssh/**",
    "${HOME}/.aws/**",
    "${HOME}/.gnupg/**",
    "${HOME}/.config/agent-gate/vault/**",
    "/etc/**",
    "/var/**",
    "/usr/**",
    "/tmp/.agent-gate-vault/**",
}

# =========================================================================
# ENVELOPE CHECKING
# =========================================================================

# A path is denied if it starts with any denied_paths prefix
path_is_denied(path) if {
    some pattern in input.envelope.denied_paths
    # Strip glob suffix for prefix matching
    prefix := trim_right(trim_right(pattern, "*"), "/")
    startswith(path, prefix)
}

# A path is allowed if it starts with any allowed_paths prefix
path_is_allowed(path) if {
    some pattern in input.envelope.allowed_paths
    prefix := trim_right(trim_right(pattern, "*"), "/")
    startswith(path, prefix)
}

# A path is outside the envelope if it's denied OR not allowed
# Denied takes precedence over allowed
path_outside_envelope(path) if {
    path_is_denied(path)
}

path_outside_envelope(path) if {
    not path_is_denied(path)
    not path_is_allowed(path)
}

# Collect all paths that are outside the envelope
paths_outside_envelope contains path if {
    some path in input.target_paths
    path_outside_envelope(path)
}

# All paths are within envelope if none are outside
all_paths_in_envelope if {
    count(paths_outside_envelope) == 0
}

# =========================================================================
# BLOCKED TIER — hard deny, check first
# =========================================================================

blocked_patterns := {
    "rm_rf_root": {
        "command": "rm",
        "args_contain": ["-rf /", "-rf ~", "-rf $HOME"],
        "description": "Recursive force delete at root or home",
    },
    "mkfs": {"command": "mkfs", "description": "Filesystem format"},
    "dd": {"command": "dd", "description": "Raw disk write"},
    "curl_pipe_bash": {
        "command": "curl",
        "args_contain": ["| bash", "| sh"],
        "description": "Piped remote execution",
    },
    "wget_pipe_bash": {
        "command": "wget",
        "args_contain": ["| bash", "| sh"],
        "description": "Piped remote execution",
    },
    "shutdown": {"command": "shutdown", "description": "System shutdown"},
    "reboot": {"command": "reboot", "description": "System reboot"},
}

# Check if args_contain triggers match
args_contain_match(triggers) if {
    full_str := concat(" ", array.concat([input.command], input.args))
    some trigger in triggers
    contains(full_str, trigger)
}

blocked_result[name] := pattern if {
    some name, pattern in blocked_patterns
    pattern.command == input.command
    not pattern.args_contain
}

blocked_result[name] := pattern if {
    some name, pattern in blocked_patterns
    pattern.command == input.command
    pattern.args_contain
    args_contain_match(pattern.args_contain)
}

# =========================================================================
# DESTRUCTIVE TIER — vault backup before allow
# =========================================================================

destructive_patterns := {
    "rm": {"command": "rm", "description": "File deletion"},
    "mv": {"command": "mv", "description": "Move/rename — source path ceases to exist"},
    "truncate": {"command": "truncate", "description": "File truncation"},
    "write_file": {
        "command": "write_file",
        "condition": "target_exists",
        "description": "Overwrite existing file",
    },
    "sed_inplace": {
        "command": "sed",
        "args_contain": ["-i"],
        "description": "In-place file edit",
    },
    "chmod": {"command": "chmod", "description": "Permission change — backup metadata"},
    "chown": {"command": "chown", "description": "Ownership change — backup metadata"},
    "cp": {
        "command": "cp",
        "condition": "target_exists",
        "description": "Copy that overwrites existing target",
    },
}

destructive_result[name] := pattern if {
    some name, pattern in destructive_patterns
    pattern.command == input.command
    not pattern.args_contain
}

destructive_result[name] := pattern if {
    some name, pattern in destructive_patterns
    pattern.command == input.command
    pattern.args_contain
    args_contain_match(pattern.args_contain)
}

# =========================================================================
# NETWORK TIER — escalate by default
# =========================================================================

network_patterns := {
    "curl": {"command": "curl", "description": "HTTP client — can download and exfiltrate data"},
    "wget": {"command": "wget", "description": "HTTP download — can fetch remote payloads"},
    "nc": {"command": "nc", "description": "Netcat — raw network connections"},
    "ssh": {"command": "ssh", "description": "Remote shell access"},
    "scp": {"command": "scp", "description": "Remote file copy"},
    "rsync": {"command": "rsync", "description": "Remote file sync"},
    "ftp": {"command": "ftp", "description": "FTP client"},
    "sftp": {"command": "sftp", "description": "Secure FTP client"},
}

network_result[name] := pattern if {
    some name, pattern in network_patterns
    pattern.command == input.command
}

# =========================================================================
# READ-ONLY TIER — auto-allow within envelope
# =========================================================================

read_only_patterns := {
    "cat": {"command": "cat"},
    "ls": {"command": "ls"},
    "head": {"command": "head"},
    "tail": {"command": "tail"},
    "grep": {"command": "grep"},
    "find": {"command": "find"},
    "wc": {"command": "wc"},
    "diff": {"command": "diff"},
    "read_file": {"command": "read_file"},
    "pwd": {"command": "pwd"},
    "echo": {"command": "echo"},
    "tree": {"command": "tree"},
}

read_only_result[name] := pattern if {
    some name, pattern in read_only_patterns
    pattern.command == input.command
}

# =========================================================================
# GATE BEHAVIOR
# =========================================================================

default network_default := "escalate"
network_message := "Network access requires approval. This command can reach external systems."

default unclassified_default := "deny"
unclassified_message := "Unclassified action. Requires human review or policy update."

vault_on_failure := "deny"

# =========================================================================
# RATE LIMITS (auto-generated from YAML)
# =========================================================================

# Per-tool rate limits
rate_limit_tools := {
    "cat": {
        "max_calls": 120,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "",
    },
    "ls": {
        "max_calls": 120,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "",
    },
    "grep": {
        "max_calls": 120,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "",
    },
    "read_file": {
        "max_calls": 120,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "",
    },
    "write_file": {
        "max_calls": 30,
        "window_seconds": 60,
        "on_exceed": "escalate",
        "message": "",
    },
    "mv": {
        "max_calls": 20,
        "window_seconds": 60,
        "on_exceed": "escalate",
        "message": "",
    },
    "cp": {
        "max_calls": 30,
        "window_seconds": 60,
        "on_exceed": "escalate",
        "message": "",
    },
    "rm": {
        "max_calls": 10,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "rm rate limit exceeded.  Max 10 calls per 60s.",
    },
    "chmod": {
        "max_calls": 5,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "",
    },
    "chown": {
        "max_calls": 5,
        "window_seconds": 60,
        "on_exceed": "deny",
        "message": "",
    },
    "curl": {
        "max_calls": 10,
        "window_seconds": 60,
        "on_exceed": "escalate",
        "message": "",
    },
    "wget": {
        "max_calls": 10,
        "window_seconds": 60,
        "on_exceed": "escalate",
        "message": "",
    },
}

# Per-tier default rate limits
rate_limit_tiers := {
    "read_only": {
        "max_calls": 120,
        "window_seconds": 60,
        "on_exceed": "deny",
    },
    "destructive": {
        "max_calls": 30,
        "window_seconds": 60,
        "on_exceed": "escalate",
    },
    "network": {
        "max_calls": 10,
        "window_seconds": 60,
        "on_exceed": "escalate",
    },
    "unclassified": {
        "max_calls": 10,
        "window_seconds": 60,
        "on_exceed": "deny",
    },
}

# Global rate limit
rate_limit_global := {
    "max_calls": 200,
    "window_seconds": 60,
    "on_exceed": "read_only",
    "message": "Global rate limit exceeded.  Agent restricted to read-only.",
}

# Circuit breaker config
circuit_breaker_config := {
    "enabled": true,
    "failure_rate_threshold": 0.5,
    "on_trip": "read_only",
    "message": "Circuit breaker tripped.  Agent restricted to read-only.",
}

# Tool rate limit check
tool_rate_exceeded[tool_name] := config if {
    input.rate_context
    some tool_name, config in rate_limit_tools
    tool_name == input.command
    tool_count := input.rate_context.tool_counts[tool_name]
    tool_count.count > config.max_calls
}

# Tier rate limit check
tier_rate_exceeded[tier_name] := config if {
    input.rate_context
    some tier_name, config in rate_limit_tiers
    tier_count := input.rate_context.tier_counts[tier_name]
    tier_count.count > config.max_calls
}

# Global rate limit check
global_rate_exceeded if {
    input.rate_context
    input.rate_context.global_count.count > rate_limit_global.max_calls
}

# Circuit breaker check
breaker_tripped if {
    input.rate_context
    circuit_breaker_config.enabled
    input.rate_context.breaker_state == "open"
}

# Aggregate: any rate limit or breaker is active
any_rate_limit_active if { breaker_tripped }
any_rate_limit_active if { count(tool_rate_exceeded) > 0 }
any_rate_limit_active if { count(tier_rate_exceeded) > 0 }
any_rate_limit_active if { global_rate_exceeded }

# =========================================================================
# DECISION — evaluated in severity order
# =========================================================================

# Priority 1: Envelope violation -> blocked
decision := result if {
    not all_paths_in_envelope
    outside := [p | some p in paths_outside_envelope]
    result := {
        "tier": "blocked",
        "reason": concat("", ["Path(s) outside envelope: ", concat(", ", outside)]),
        "paths_in_envelope": false,
        "paths_outside_envelope": outside,
        "matched_pattern": null,
    }
}
# Priority 1.5: Circuit breaker tripped -> rate_limited
decision := result if {
    all_paths_in_envelope
    breaker_tripped
    result := {
        "tier": "rate_limited",
        "reason": circuit_breaker_config.message,
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": null,
        "rate_action": circuit_breaker_config.on_trip,
    }
}

# Priority 1.6: Per-tool rate limit exceeded
decision := result if {
    all_paths_in_envelope
    not breaker_tripped
    some tool_name, config in tool_rate_exceeded
    result := {
        "tier": "rate_limited",
        "reason": config.message,
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": null,
        "rate_action": config.on_exceed,
    }
}

# Priority 1.7: Per-tier rate limit exceeded
decision := result if {
    all_paths_in_envelope
    not breaker_tripped
    count(tool_rate_exceeded) == 0
    some tier_name, config in tier_rate_exceeded
    result := {
        "tier": "rate_limited",
        "reason": concat("", [tier_name, " tier rate limit exceeded."]),
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": null,
        "rate_action": config.on_exceed,
    }
}

# Priority 1.8: Global rate limit exceeded
decision := result if {
    all_paths_in_envelope
    not breaker_tripped
    count(tool_rate_exceeded) == 0
    count(tier_rate_exceeded) == 0
    global_rate_exceeded
    result := {
        "tier": "rate_limited",
        "reason": rate_limit_global.message,
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": null,
        "rate_action": rate_limit_global.on_exceed,
    }
}
# Priority 2: Blocked tier match (rate limits take precedence)
decision := result if {
    all_paths_in_envelope
    not any_rate_limit_active
    some name, pattern in blocked_result
    result := {
        "tier": "blocked",
        "reason": pattern.description,
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": pattern,
    }
}

# Priority 3: Destructive tier match (only if not blocked)
decision := result if {
    all_paths_in_envelope
    not any_rate_limit_active
    count(blocked_result) == 0
    some name, pattern in destructive_result
    result := {
        "tier": "destructive",
        "reason": pattern.description,
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": pattern,
    }
}

# Priority 4: Network tier (only if not blocked or destructive)
decision := result if {
    all_paths_in_envelope
    not any_rate_limit_active
    count(blocked_result) == 0
    count(destructive_result) == 0
    some name, pattern in network_result
    result := {
        "tier": "network",
        "reason": pattern.description,
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": pattern,
    }
}

# Priority 5: Read-only (only if nothing higher matched)
decision := result if {
    all_paths_in_envelope
    not any_rate_limit_active
    count(blocked_result) == 0
    count(destructive_result) == 0
    count(network_result) == 0
    some name, pattern in read_only_result
    result := {
        "tier": "read_only",
        "reason": "Read-only action within envelope",
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": pattern,
    }
}

# Priority 6: Unclassified (nothing matched)
default decision := {
    "tier": "unclassified",
    "reason": "No matching pattern in policy. Requires human review.",
    "paths_in_envelope": true,
    "paths_outside_envelope": [],
    "matched_pattern": null,
}
