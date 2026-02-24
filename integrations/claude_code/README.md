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
- **Network operations** (curl, wget, ssh) — escalated for human approval by default
- **Non-literal commands** (`rm $VAR`, `$(cmd)`, globs) — denied before classification; agent told to rewrite with literal values
- **Envelope violations** (paths outside allowed zone) — hard denied, symlinks resolved
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

## Sub-agent Governance

### How enforcement works automatically

Agent Gate's policy enforcement applies to every Claude Code agent in a session, including parent agents, sub-agents spawned via Task, and any further nesting, without additional configuration.  Two mechanisms combine to produce this:

First, hook registrations in `~/.claude/settings.json` or `.claude/settings.json` apply to all Claude Code sessions on that machine, including sub-agent sessions.  When a sub-agent makes a tool call, the same PreToolUse hooks fire.

Second, sub-agent processes inherit the parent process environment.  `AGENT_GATE_POLICY`, `AGENT_GATE_WORKDIR`, and all identity variables (`AGENT_GATE_SESSION`, `AGENT_GATE_ROLE`, etc.) are present in every sub-agent's environment automatically.

Both the Python/YAML backend and the OPA/Rego backend are covered.  OPA subprocess mode evaluates against the same Rego files.  OPA HTTP mode calls the same sidecar endpoint via the inherited URL.  A destructive action blocked for the parent is equally blocked for any sub-agent.

### Clarification on GitHub #25000

GitHub #25000 and related issues describe sub-agents bypassing deny rules in Claude Code.  This is a bug in Claude Code's native permission system, `deny` entries in `settings.json` do not propagate to sub-agents via Claude Code's own mechanism.  Agent Gate's enforcement layer is separate and is not affected.  Operators using Agent Gate do not need to wait for a Claude Code fix.  Enforcement already propagates through the hook and environment inheritance mechanism described above.

### Configuring distinct policies for specific sub-agents

Operators who need a sub-agent to run under a different policy can override `AGENT_GATE_POLICY` using Claude Code's subagent frontmatter `hooks:` section.  All other environment variables are inherited from the parent session.

```yaml
---
name: production-db-agent
description: Agent with access to production database tools
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: >
            AGENT_GATE_POLICY=~/.config/agent-gate/policy-production.yaml
            AGENT_GATE_ROLE=restricted
            python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook.py
---
You are an agent with access to production database tools.
Only run queries explicitly requested.  Never modify schema.
```

### Capturing agent hierarchy in audit records

Audit records can include agent depth and parent session ID when the operator sets `AGENT_GATE_DEPTH` and `AGENT_GATE_PARENT_SESSION` in subagent frontmatter.  This is optional.  When not set, audit records and gate behavior are identical to v0.4.0.  When set, hierarchy fields appear in every audit record for that sub-agent and can be visualized with `agent-gate tree <session_id>`.

Add these variables to the frontmatter hooks command:

```yaml
command: >
  AGENT_GATE_DEPTH=1
  AGENT_GATE_PARENT_SESSION=${AGENT_GATE_SESSION}
  python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook.py
```

## Known Limitations

**What this is and isn't.**

This is a safety net for well-intentioned agents making mistakes. It is not a security boundary against adversarial agents.

- **Literal-only enforcement** catches shell expansion syntax and interpreter inline code, but programs can compute behavior internally — `python3 script.py` where the script contains `os.remove()` is literal to the gate but computed inside Python
- **Compound command splitting** is regex-based (`&&`, `||`, `;`, `|`) — nested or quoted delimiters may split incorrectly
- **Path extraction** treats all non-flag arguments as potential paths, which is naive but conservative
- This is application-layer gating, not OS-level sandboxing
- The gate trusts that Claude Code routes all tool calls through the hook system

## Dependencies

- Python 3.9+
- PyYAML (`pip install pyyaml`)
- The `agent_gate` package (from this repo, via PYTHONPATH)