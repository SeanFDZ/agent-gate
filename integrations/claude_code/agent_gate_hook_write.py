#!/usr/bin/env python3
"""
agent_gate_hook_write.py — Claude Code PreToolUse hook for Write/Edit tools.

Gates file write and edit operations: envelope check + vault backup.
Exit 0 = allow, Exit 2 = block.
"""

import sys
import os
import json
import shutil
import yaml
from datetime import datetime

POLICY_PATH = os.path.expanduser("~/agent-gate-test/policy.yaml")
LOG_PATH = os.path.expanduser("~/agent-gate-test/gate.log")


def log(message):
    timestamp = datetime.now().isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def load_policy():
    with open(POLICY_PATH) as f:
        return yaml.safe_load(f)


def check_envelope(path, policy):
    allowed = policy.get("envelope", {}).get("allowed_paths", [])
    denied = policy.get("envelope", {}).get("denied_paths", [])

    for d in denied:
        pattern = d.rstrip("*").rstrip("/")
        if path.startswith(pattern):
            return False, f"ENVELOPE VIOLATION: {path} is in denied zone ({d})"

    for a in allowed:
        pattern = a.rstrip("*").rstrip("/")
        if path.startswith(pattern):
            return True, None

    return False, f"ENVELOPE VIOLATION: {path} is outside allowed paths"


def vault_backup(path, vault_dir):
    if not os.path.exists(path):
        return True, None  # New file, nothing to back up

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vault_target = os.path.join(vault_dir, timestamp, path.lstrip("/"))
    os.makedirs(os.path.dirname(vault_target), exist_ok=True)

    try:
        if os.path.isdir(path):
            shutil.copytree(path, vault_target, dirs_exist_ok=True)
        else:
            shutil.copy2(path, vault_target)
        log(f"VAULT BACKUP: {path} -> {vault_target}")
        return True, vault_target
    except Exception as e:
        log(f"VAULT BACKUP FAILED: {path} -- {e}")
        return False, None


def main():
    try:
        hook_input = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Write tool uses file_path, Edit tool uses file_path
    file_path = tool_input.get("file_path", "")
    if not file_path:
        sys.exit(0)

    # Resolve to absolute path
    file_path = os.path.abspath(os.path.expanduser(file_path))

    log(f"HOOK INTERCEPTED ({tool_name}): {file_path}")

    policy = load_policy()
    vault_dir = policy.get("vault", {}).get("path", "")

    # Envelope check
    envelope_ok, reason = check_envelope(file_path, policy)
    if not envelope_ok:
        log(f"DENIED ({tool_name}): {file_path} -- {reason}")
        print(f"[AGENT GATE] DENIED: {reason}. {tool_name} to '{file_path}' blocked.", file=sys.stderr)
        sys.exit(2)

    # Vault backup before overwrite (only if file already exists)
    if os.path.exists(file_path):
        log(f"DESTRUCTIVE ({tool_name}) — file exists, backing up: {file_path}")
        backup_ok, vault_target = vault_backup(file_path, vault_dir)
        if not backup_ok:
            log(f"DENIED ({tool_name}): {file_path} -- vault backup failed")
            print(f"[AGENT GATE] DENIED: Vault backup failed. No snapshot, no destruction.", file=sys.stderr)
            sys.exit(2)
        log(f"ALLOW ({tool_name}, vault backup complete): {file_path}")
    else:
        log(f"ALLOW ({tool_name}, new file): {file_path}")

    sys.exit(0)


if __name__ == "__main__":
    main()
