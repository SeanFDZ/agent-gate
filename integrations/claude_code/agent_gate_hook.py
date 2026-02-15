#!/usr/bin/env python3
"""
agent_gate_hook.py — Claude Code PreToolUse hook for Agent Gate.

Receives tool call JSON on stdin from Claude Code's hook system.
Classifies the command, enforces envelope, backs up before destruction.
Exit 0 = allow, Exit 2 = block.
"""

import sys
import os
import json
import shutil
import shlex
import yaml
from datetime import datetime

POLICY_PATH = os.path.expanduser("~/agent-gate-test/policy.yaml")
LOG_PATH = os.path.expanduser("~/agent-gate-test/gate.log")


def log(message):
    timestamp = datetime.now().isoformat()
    entry = f"[{timestamp}] {message}"
    with open(LOG_PATH, "a") as f:
        f.write(entry + "\n")


def load_policy():
    with open(POLICY_PATH) as f:
        return yaml.safe_load(f)


def split_compound_command(cmd_string):
    import re
    parts = re.split(r'\s*(?:&&|\|\||;|\|)\s*', cmd_string)
    return [p.strip() for p in parts if p.strip()]


def parse_command(cmd_string):
    try:
        parts = shlex.split(cmd_string)
    except ValueError:
        parts = cmd_string.split()
    if not parts:
        return None, [], []
    base_cmd = os.path.basename(parts[0])
    flags = [p for p in parts[1:] if p.startswith("-")]
    args = [p for p in parts[1:] if not p.startswith("-")]
    return base_cmd, flags, args


def resolve_paths(args):
    resolved = []
    for a in args:
        if "=" in a:
            continue
        resolved.append(os.path.abspath(os.path.expanduser(a)))
    return resolved


def check_envelope(paths, policy):
    allowed = policy.get("envelope", {}).get("allowed_paths", [])
    denied = policy.get("envelope", {}).get("denied_paths", [])
    for path in paths:
        for d in denied:
            pattern = d.rstrip("*").rstrip("/")
            if path.startswith(pattern):
                return False, f"ENVELOPE VIOLATION: {path} is in denied zone ({d})"
        in_allowed = False
        for a in allowed:
            pattern = a.rstrip("*").rstrip("/")
            if path.startswith(pattern):
                in_allowed = True
                break
        if not in_allowed:
            return False, f"ENVELOPE VIOLATION: {path} is outside allowed paths"
    return True, None


def classify(base_cmd, policy):
    actions = policy.get("actions", {})
    for item in actions.get("read_only", []):
        if item.get("pattern") == base_cmd:
            return "read_only"
    for item in actions.get("destructive", []):
        if item.get("pattern") == base_cmd:
            return "destructive"
    for item in actions.get("blocked", []):
        if item.get("pattern") == base_cmd:
            return "blocked"
    return "unknown"


def check_blocked_patterns(cmd_string, policy):
    import re
    actions = policy.get("actions", {})
    for item in actions.get("blocked", []):
        pattern = item.get("pattern", "")
        # Match pattern only at word boundary — "rm -rf /" must not match "rm -rf /Users/..."
        regex_pattern = re.escape(pattern) + r'(\s|$)'
        if re.search(regex_pattern, cmd_string):
            return True, f"BLOCKED PATTERN: '{pattern}' matched"
    return False, None


def vault_backup(paths, vault_dir):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backed_up = []
    for path in paths:
        if not os.path.exists(path):
            continue
        vault_target = os.path.join(vault_dir, timestamp, path.lstrip("/"))
        os.makedirs(os.path.dirname(vault_target), exist_ok=True)
        try:
            if os.path.isdir(path):
                shutil.copytree(path, vault_target, dirs_exist_ok=True)
            else:
                shutil.copy2(path, vault_target)
            backed_up.append((path, vault_target))
            log(f"VAULT BACKUP: {path} -> {vault_target}")
        except Exception as e:
            log(f"VAULT BACKUP FAILED: {path} -- {e}")
            return False, backed_up
    return True, backed_up


def main():
    # Read hook input from stdin
    try:
        hook_input = json.load(sys.stdin)
    except Exception:
        # If we can't parse input, allow (fail open for non-Bash tools)
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Only gate Bash commands
    if tool_name != "Bash":
        sys.exit(0)

    cmd_string = tool_input.get("command", "")
    if not cmd_string.strip():
        sys.exit(0)

    log(f"HOOK INTERCEPTED: {cmd_string}")

    policy = load_policy()
    vault_dir = policy.get("vault", {}).get("path", "")

    # Check blocked patterns on full command
    is_blocked, reason = check_blocked_patterns(cmd_string, policy)
    if is_blocked:
        log(f"BLOCKED: {cmd_string} -- {reason}")
        print(f"[AGENT GATE] BLOCKED: {reason}. Command '{cmd_string}' is prohibited by policy.", file=sys.stderr)
        sys.exit(2)

    # Decompose compound commands and gate each
    sub_commands = split_compound_command(cmd_string)

    for sub_cmd in sub_commands:
        base_cmd, flags, args = parse_command(sub_cmd)
        if base_cmd is None:
            continue

        classification = classify(base_cmd, policy)
        paths = resolve_paths(args)

        if paths:
            envelope_ok, envelope_reason = check_envelope(paths, policy)
            if not envelope_ok:
                log(f"DENIED: {cmd_string} -- sub-command '{sub_cmd}' -- {envelope_reason}")
                print(f"[AGENT GATE] DENIED: {envelope_reason}. Sub-command '{sub_cmd}' violates envelope. Entire command blocked.", file=sys.stderr)
                sys.exit(2)

        if classification == "blocked":
            log(f"BLOCKED: {cmd_string} -- sub-command '{sub_cmd}'")
            print(f"[AGENT GATE] BLOCKED: '{sub_cmd}' is prohibited by policy.", file=sys.stderr)
            sys.exit(2)

    # All sub-commands passed — vault backup for destructive ones
    all_destructive_paths = []
    for sub_cmd in sub_commands:
        base_cmd, flags, args = parse_command(sub_cmd)
        if base_cmd is None:
            continue
        if classify(base_cmd, policy) == "destructive":
            all_destructive_paths.extend(resolve_paths(args))

    if all_destructive_paths:
        log(f"DESTRUCTIVE ACTION — initiating vault backup: {all_destructive_paths}")
        backup_ok, backups = vault_backup(all_destructive_paths, vault_dir)
        if not backup_ok:
            log(f"DENIED: {cmd_string} -- vault backup failed")
            print(f"[AGENT GATE] DENIED: Vault backup failed. No snapshot, no destruction.", file=sys.stderr)
            sys.exit(2)
        log(f"ALLOW (vault backup complete): {cmd_string}")
        for original, vault_loc in backups:
            log(f"  backed up: {original} -> {vault_loc}")
    else:
        log(f"ALLOW: {cmd_string}")

    # Exit 0 = allow the command to proceed
    sys.exit(0)


if __name__ == "__main__":
    main()
