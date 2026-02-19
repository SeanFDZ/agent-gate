# Agent Gate — OPA Policy
# Rego equivalent of the YAML policy definitions.
#
# This policy evaluates structured tool call input and returns
# a classification decision with tier, reason, and envelope status.
#
# Input document (provided by OPAClassifier):
# {
#   "command": "rm",
#   "args": ["-f", "/workspace/file.txt"],
#   "target_paths": ["/workspace/file.txt"],
#   "tool": "bash",
#   "raw_input": {...},
#   "envelope": {
#     "allowed_paths": ["/workspace/**"],
#     "denied_paths": ["/etc/**", "~/.config/agent-gate/vault/**"]
#   }
# }
#
# Output (decision document):
# {
#   "tier": "destructive",
#   "reason": "File deletion",
#   "paths_in_envelope": true,
#   "paths_outside_envelope": [],
#   "matched_pattern": {"command": "rm", "description": "File deletion"}
# }

package agent_gate

import future.keywords.in
import future.keywords.every
import future.keywords.contains
import future.keywords.if

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
    "mkfs": {
        "command": "mkfs",
        "description": "Filesystem format",
    },
    "dd": {
        "command": "dd",
        "description": "Raw disk write",
    },
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
    "shutdown": {
        "command": "shutdown",
        "description": "System shutdown",
    },
    "reboot": {
        "command": "reboot",
        "description": "System reboot",
    },
}

# Check if args_contain triggers match
args_contain_match(triggers) if {
    full_str := concat(" ", array.concat([input.command], input.args))
    some trigger in triggers
    contains(full_str, trigger)
}

# A blocked pattern matches if command matches and args_contain (if present) matches
# Returns object (name → pattern) so decision rules can access the pattern directly.
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
    "rm": {
        "command": "rm",
        "description": "File deletion",
    },
    "mv": {
        "command": "mv",
        "description": "Move/rename — source path ceases to exist",
    },
    "truncate": {
        "command": "truncate",
        "description": "File truncation",
    },
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
    "chmod": {
        "command": "chmod",
        "description": "Permission change — backup metadata",
    },
    "chown": {
        "command": "chown",
        "description": "Ownership change — backup metadata",
    },
    "cp_overwrite": {
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
    "curl": {"command": "curl", "description": "HTTP client"},
    "wget": {"command": "wget", "description": "HTTP download"},
    "nc":   {"command": "nc",   "description": "Netcat"},
    "ssh":  {"command": "ssh",  "description": "Remote shell access"},
    "scp":  {"command": "scp",  "description": "Remote file copy"},
    "rsync": {"command": "rsync", "description": "Remote file sync"},
    "ftp":  {"command": "ftp",  "description": "FTP client"},
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
    "cat":  {"command": "cat"},
    "ls":   {"command": "ls"},
    "head": {"command": "head"},
    "tail": {"command": "tail"},
    "grep": {"command": "grep"},
    "find": {"command": "find"},
    "wc":   {"command": "wc"},
    "diff": {"command": "diff"},
    "read_file": {"command": "read_file"},
    "pwd":  {"command": "pwd"},
    "echo": {"command": "echo"},
    "tree": {"command": "tree"},
}

read_only_result[name] := pattern if {
    some name, pattern in read_only_patterns
    pattern.command == input.command
}

# =========================================================================
# DECISION — evaluated in severity order
# =========================================================================

# Priority 1: Envelope violation → blocked
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

# Priority 2: Blocked tier match
decision := result if {
    all_paths_in_envelope
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
