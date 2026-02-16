#!/usr/bin/env python3
"""
agent_gate_hook.py — Claude Code PreToolUse hook for Agent Gate (Bash).

Thin adapter between Claude Code's hook system and the Agent Gate core library.
All classification, envelope enforcement, and vault logic lives in agent_gate/.

Receives tool call JSON on stdin, delegates to Gate.evaluate(), maps verdict to exit code.
Exit 0 = allow, Exit 2 = block.

Configuration via environment variables:
  AGENT_GATE_POLICY  — Path to policy YAML (required, or set default below)
  AGENT_GATE_WORKDIR — Agent working directory (defaults to cwd)
"""

import sys
import os
import json
import re

# Ensure the agent_gate package is importable.
# Adjust this path if the repo lives somewhere else on your system.
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


def split_compound_command(cmd_string):
    """
    Split bash compound commands (&&, ||, ;, |) into individual commands.
    This is a bash-specific concern — the core library classifies single commands.
    """
    parts = re.split(r'\s*(?:&&|\|\||;|\|)\s*', cmd_string)
    return [p.strip() for p in parts if p.strip()]


def main():
    # Read hook input from stdin (Claude Code's PreToolUse format)
    try:
        hook_input = json.load(sys.stdin)
    except Exception:
        # Can't parse input — fail open for non-Bash tools
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Only gate Bash commands
    if tool_name != "Bash":
        sys.exit(0)

    cmd_string = tool_input.get("command", "")
    if not cmd_string.strip():
        sys.exit(0)

    # Initialize the gate (loads policy, classifier, vault)
    try:
        gate = Gate(policy_path=POLICY_PATH, workdir=WORKDIR)
    except Exception as e:
        # If gate can't initialize, fail closed
        print(
            f"[AGENT GATE] ERROR: Gate initialization failed: {e}",
            file=sys.stderr,
        )
        sys.exit(2)

    # Split compound commands and evaluate each sub-command.
    # If any sub-command is denied, the entire compound command is blocked.
    sub_commands = split_compound_command(cmd_string)

    for sub_cmd in sub_commands:
        # Translate to core tool call format
        tool_call = {
            "tool": "bash",
            "input": {"command": sub_cmd},
        }

        decision = gate.evaluate(tool_call)

        if not decision.allowed:
            msg = decision.to_agent_message()
            print(f"[AGENT GATE] {msg}", file=sys.stderr)
            sys.exit(2)

    # All sub-commands passed — allow execution
    sys.exit(0)


if __name__ == "__main__":
    main()