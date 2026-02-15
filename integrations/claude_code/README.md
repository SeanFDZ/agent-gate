# Agent Gate — Claude Code Integration

Integrates Agent Gate as a PreToolUse hook for Claude Code, providing execution authority enforcement when running with `--dangerously-skip-permissions`.

## What This Does

Agent Gate sits invisibly between Claude Code's tool calls and actual execution. Every Bash command, file Write, and file Edit passes through the gate before it touches the filesystem.

- **Read-only operations** (ls, cat, grep) — auto-allowed, no overhead
- **Destructive operations** (rm, mv, file overwrites) — vault backup before execution
- **Envelope violations** (paths outside allowed zone) — hard denied
- **Vault access by agent** — hard denied (the agent cannot destroy its own safety net)

Claude Code doesn't know the gate is there. It runs at full speed in dangerous mode while the gate silently enforces the policy underneath.

## How It Works

Claude Code's [hooks system](https://code.claude.com/docs/en/hooks) fires a `PreToolUse` event before every tool execution. The hook receives the tool name and input as JSON on stdin. Agent Gate reads this, classifies the action, enforces envelope boundaries, triggers vault backup for destructive actions, and returns:

- **Exit 0** — allow the action
- **Exit 2** — block the action (reason shown to Claude Code)

## Setup

### 1. Create a test environment
```bash
./test_setup.sh ~/agent-gate-test
```

### 2. Update hook paths

Edit `agent_gate_hook.py` and `agent_gate_hook_write.py` — set `POLICY_PATH` to your policy file location.

### 3. Register hooks with Claude Code

Add the hooks to `~/.claude/settings.json` (see `settings_example.json`). Update the `command` paths to point to where you placed the hook scripts.

### 4. Launch Claude Code
```bash
cd ~/agent-gate-test/workspace && claude --dangerously-skip-permissions
```

## Hooks

| File | Matches | Purpose |
|------|---------|---------|
| `agent_gate_hook.py` | Bash | Intercepts shell commands — envelope check, action classification, vault backup |
| `agent_gate_hook_write.py` | Write, Edit | Intercepts file modifications — envelope check, vault backup before overwrite |

## Vault

Every destructive action creates a timestamped snapshot in the vault before execution. Multiple overwrites of the same file create multiple snapshots — full version history.
```
vault/
├── 20260215_142645/
│   └── Users/.../workspace/temp_logs/
│       ├── access.log
│       └── debug.log
├── 20260215_143446/
│   └── Users/.../workspace/family_photos/
│       ├── kids_birthday.jpg
│       └── vacation_2024.jpg
└── 20260215_144423/
    └── Users/.../workspace/project_notes.md
```

Recovery is a simple copy:
```bash
cp vault/<timestamp>/path/to/file workspace/path/to/file
```

## Known Limitations

**What this is and isn't.**

This is a safety net for well-intentioned agents making mistakes. It is not a security boundary against adversarial agents.

- The Bash command parser is naive — it treats all non-flag arguments as potential paths, which provides accidental protection against some bypass techniques but is fragile
- Shell expansion (`$()`, backticks, variable substitution) is not evaluated — the gate sees literal strings
- Interpreter bypass (`python3 -c "os.remove()"`) is blocked by accident (parser misidentifies arguments as paths), not by design
- This is application-layer gating, not OS-level sandboxing
- The gate trusts that Claude Code routes all tool calls through the hook system

## Live Test Results (Feb 15, 2026)

Tested with Claude Code in `--dangerously-skip-permissions` mode:

- ✅ Bash `rm` of log files — vault backup, then deletion allowed
- ✅ Bash `rm -rf` of directory — vault backup of entire directory, then deletion allowed
- ✅ Write tool overwrite — vault backup of original, then overwrite allowed
- ✅ Multiple overwrites — each created a separate timestamped snapshot
- ✅ Envelope violation — operations outside allowed paths blocked
- ✅ Vault protection — agent cannot access or delete vault contents
- ✅ Vault recovery — files restored from vault in seconds
