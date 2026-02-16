# Agent Gate — Claude Code Integration

Integrates Agent Gate as a PreToolUse hook for Claude Code, providing execution authority enforcement when running with `--dangerously-skip-permissions`.

## Architecture

The hooks are thin adapters — they translate Claude Code's hook format to the core `agent_gate` library and map verdicts back to exit codes. All classification, envelope enforcement, and vault logic lives in `agent_gate/` (single source of truth).
```
Claude Code tool call → PreToolUse hook → Gate.evaluate() → GateDecision → Exit 0/2
```

## What This Does

Agent Gate sits invisibly between Claude Code's tool calls and actual execution. Every Bash command, file Write, and file Edit passes through the gate before it touches the filesystem.

- **Read-only operations** (ls, cat, grep) — auto-allowed, no overhead
- **Destructive operations** (rm, mv, file overwrites) — vault backup before execution
- **Envelope violations** (paths outside allowed zone) — hard denied
- **Blocked patterns** (rm -rf /, piped remote execution) — hard denied
- **Vault access by agent** — hard denied (the agent cannot destroy its own safety net)

Claude Code doesn't know the gate is there. It runs at full speed in dangerous mode while the gate silently enforces the policy underneath.

## How It Works

Claude Code's [hooks system](https://code.claude.com/docs/en/hooks) fires a `PreToolUse` event before every tool execution. The hook receives the tool name and input as JSON on stdin. The hook translates this to the core library's tool call format, calls `Gate.evaluate()`, and returns:

- **Exit 0** — allow the action
- **Exit 2** — block the action (structured denial reason shown to Claude Code)

Denial messages include why the action was blocked and what would be required to proceed (escalation path), using the core library's `GateDecision.to_agent_message()`.

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/SeanFDZ/agent-gate.git ~/projects/agent-gate
```

### 2. Configure environment

The hooks use environment variables for configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_GATE_POLICY` | `~/projects/agent-gate/policies/default.yaml` | Path to policy YAML |
| `AGENT_GATE_WORKDIR` | Current working directory | Agent's allowed workspace |

### 3. Register hooks with Claude Code

Add the hooks to `~/.claude/settings.json` (see `settings_example.json`). Update the `command` paths to match your system. Example:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "PYTHONPATH=~/projects/agent-gate python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook.py"
        }]
      },
      {
        "matcher": "Write",
        "hooks": [{
          "type": "command",
          "command": "PYTHONPATH=~/projects/agent-gate python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook_write.py"
        }]
      },
      {
        "matcher": "Edit",
        "hooks": [{
          "type": "command",
          "command": "PYTHONPATH=~/projects/agent-gate python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook_write.py"
        }]
      }
    ]
  }
}
```

### 4. Launch Claude Code
```bash
cd ~/your/project && claude --dangerously-skip-permissions
```

## Hooks

| File | Matches | Purpose |
|------|---------|---------|
| `agent_gate_hook.py` | Bash | Splits compound commands, evaluates each via `Gate.evaluate()` |
| `agent_gate_hook_write.py` | Write, Edit | Resolves file path, evaluates via `Gate.evaluate()` |

Both hooks import and call the `agent_gate` core library. No classification, envelope, or vault logic is duplicated in the hooks.

## Vault

Every destructive action creates a snapshot in the vault before execution. Snapshots are organized by path hash with SHA-256 integrity verification and a JSONL manifest.
```
vault/
├── manifest.jsonl          # Structured audit log of all snapshots
├── 2d7076113d8c/           # Path hash for file A
│   ├── 20260216_142645_README.md
│   └── 20260216_153012_README.md
└── a8f3bc9e1d04/           # Path hash for file B
    └── 20260216_143446_config.yaml
```

Recovery uses the CLI:
```bash
cd ~/projects/agent-gate
python3 -m agent_gate.cli list
python3 -m agent_gate.cli restore <vault_path>
```

## Known Limitations

**What this is and isn't.**

This is a safety net for well-intentioned agents making mistakes. It is not a security boundary against adversarial agents.

- **Compound command splitting** is regex-based (`&&`, `||`, `;`, `|`) — nested or quoted delimiters may split incorrectly
- **Path extraction** treats all non-flag arguments as potential paths, which is naive but conservative
- **Shell expansion** (`$()`, backticks, variable substitution) is not evaluated — the gate sees literal strings
- **Interpreter bypass** (`python3 -c "os.remove()"`) is not reliably caught
- **Policy conditions** (e.g., `target_exists` for write_file) are declared in policy YAML but not yet enforced by the classifier
- This is application-layer gating, not OS-level sandboxing
- The gate trusts that Claude Code routes all tool calls through the hook system

## Dependencies

- Python 3.9+
- PyYAML (`pip install pyyaml`)
- The `agent_gate` package (from this repo, via PYTHONPATH)