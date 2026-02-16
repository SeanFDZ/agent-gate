#!/usr/bin/env python3
"""
agent_gate_hook_write.py — Claude Code PreToolUse hook for Write/Edit tools.

Thin adapter between Claude Code's Write/Edit hooks and the Agent Gate core library.
All classification, envelope enforcement, and vault logic lives in agent_gate/.

Exit 0 = allow, Exit 2 = block.

Configuration via environment variables:
  AGENT_GATE_POLICY  — Path to policy YAML (required, or set default below)
  AGENT_GATE_WORKDIR — Agent working directory (defaults to cwd)
"""

import sys
import os
import json

# Ensure the agent_gate package is importable.
AGENT_GATE_ROOT = os.path.expanduser("~/projects/agent-gate")
if AGENT_GATE_ROOT not in sys.path:
    sys.path.insert(0, AGENT_GATE_ROOT)

from agent_gate.gate import Gate, Verdict

# --- Configuration ---
POLICY_PATH = os.environ.get(
    "AGENT_GATE_POLICY",
    os.path.join(AGENT_GATE_ROOT, "policies", "default.yaml"),
)
WORKDIR = os.environ.get("AGENT_GATE_WORKDIR", os.getcwd())


def main():
    # Read hook input from stdin (Claude Code's PreToolUse format)
    try:
        hook_input = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Only gate Write and Edit tools
    if tool_name not in ("Write", "Edit"):
        sys.exit(0)

    file_path = tool_input.get("file_path", "")
    if not file_path:
        sys.exit(0)

    # Resolve to absolute path (handle ~ and relative paths)
    file_path = os.path.abspath(os.path.expanduser(file_path))

    # Initialize the gate
    try:
        gate = Gate(policy_path=POLICY_PATH, workdir=WORKDIR)
    except Exception as e:
        print(
            f"[AGENT GATE] ERROR: Gate initialization failed: {e}",
            file=sys.stderr,
        )
        sys.exit(2)

    # Translate to core tool call format.
    # Write/Edit map to "write_file" which the classifier checks
    # for envelope + destructive (if target exists).
    tool_call = {
        "tool": "write_file",
        "input": {"path": file_path},
    }

    decision = gate.evaluate(tool_call)

    if not decision.allowed:
        msg = decision.to_agent_message()
        print(f"[AGENT GATE] {msg}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()