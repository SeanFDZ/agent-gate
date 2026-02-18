# Agent Gate

**Execution authority layer for AI agents - vault-backed rollback and policy enforcement.**

Agent Gate sits between an AI agent's proposed tool calls and their execution. It inspects every action as structured data, classifies it against pre-computed policy, enforces directory boundaries, and automatically backs up targets to an agent-unreachable vault before any destructive operation proceeds.

The agent runs at full autonomy and full speed. The gate silently ensures every destructive action is reversible and every action stays within the authorized envelope.

## The Problem

AI agents are gaining the ability to act autonomously — deleting files, modifying configs, writing to databases. The current guardrail ecosystem focuses on what the LLM *says* (content safety). Almost nobody is building the authority layer that controls what the agent *does* before it does it.

Existing solutions either:

- **Trust the agent to manage its own safety** — the agent backs up its own files, which means the agent can also delete the backups
- **Block destructive actions entirely** — which stalls the agent and makes the denial itself the damage

Agent Gate takes a different approach: **make every action safe to allow.**

## The Core Insight

Every AI agent framework follows the same pattern:
```
Agent reasons → Agent outputs structured tool call (JSON) → Client executes
```

The model never touches the world directly. That gap between "proposed" and "executed" is the gate insertion point — and it already exists in every framework.

## How It Works
```
Agent proposes: rm important.txt
         │
         ▼
   ┌─────────────┐
   │  AGENT GATE │
   ├─────────────┤
   │ 1. Literal? │  ← reject shell expansion ($VAR, $(cmd), globs)
   │ 2. Classify │  ← "rm" = destructive action
   │ 3. Envelope │  ← is resolved path authorized? (follows symlinks)
   │ 4. Vault    │  ← copy important.txt to vault
   │ 5. Allow    │  ← backup confirmed, proceed
   └─────────────┘
         │
         ▼
   rm important.txt executes
```

If the command contains shell expansion syntax, it's rejected before classification — the gate can't trust extracted paths when the shell would transform the command. The agent is told to rewrite using literal values.

If the backup fails, the destructive action is blocked. No snapshot, no destruction.

The vault lives outside the agent's permitted directory envelope. The same gate that enforces the envelope protects the vault. The agent cannot reach, modify, or delete the backups.

## Design Principles

1. **Prevention over auditability.** Audit trails are necessary but not sufficient. The architecture makes damage reversible, not just logged.
2. **Pre-computed classification, not runtime evaluation.** Risk tiers and rules are defined at design time. The runtime check is a lookup, not an LLM call.
3. **Inspect the action, not the reasoning.** We don't need to understand why an agent wants to delete a file. We see "rm" targeting a path and match it against policy.
4. **Literal-only enforcement.** The gate defines what "clean" looks like — literal paths, flags, and simple values — and rejects anything else. Shell expansion syntax (`$VAR`, `$(cmd)`, globs, backticks) is denied before classification because the gate can't trust paths it can't read. This is an allowlist on arguments, not a blocklist on shell tricks.
5. **Tiered response.** Auto-allow safe actions, vault-backup destructive ones, escalate network access, hard-stop prohibited ones.
6. **Structured denial feedback.** The gate doesn't just say "no." It returns why and what would be required to proceed.

## Tiered Classification

| Tier | Examples | Gate Behavior |
|------|----------|---------------|
| **Read-only** | `cat`, `ls`, `grep`, `find` | Auto-allow within envelope |
| **Destructive** | `rm`, `mv`, `sed -i`, overwrite | Backup to vault, then allow |
| **Network** | `curl`, `wget`, `ssh`, `scp` | Escalate for human approval (configurable) |
| **Blocked** | `rm -rf /`, `curl \| bash`, `mkfs` | Hard deny with feedback |
| **Unclassified** | Anything not in policy | Default deny, request human review |

## Claude Code Integration (Live Tested)

Agent Gate integrates with Claude Code via [PreToolUse hooks](https://code.claude.com/docs/en/hooks), intercepting Bash commands, file Writes, and file Edits before execution. Claude Code runs at full speed with `--dangerously-skip-permissions` while the gate silently enforces the policy underneath.

### Live Test Results (48/48 passing — Feb 18, 2026)

| Scenario | Result |
|----------|--------|
| `rm` log files | ✅ Vault backup, then deletion allowed |
| `rm -rf` directory of "family photos" | ✅ Entire directory backed up, then deletion allowed |
| Write tool overwrites file contents | ✅ Original backed up, overwrite allowed |
| Write tool creates new file | ✅ Allowed without vault backup (nothing to destroy) |
| Multiple overwrites of same file | ✅ Each created a separate timestamped snapshot |
| Operation outside allowed paths | ✅ Blocked — envelope violation |
| Symlink inside workspace → `/etc/` | ✅ Blocked — resolved path outside envelope |
| Symlink inside workspace → vault | ✅ Blocked — vault is unreachable |
| Agent tries to access/delete vault | ✅ Blocked — vault is unreachable |
| Compound commands (`cd /tmp && rm file`) | ✅ Decomposed and each sub-command gated |
| `rm $TARGET` (variable expansion) | ✅ Blocked — non-literal command |
| `rm $(cat targets.txt)` (command substitution) | ✅ Blocked — non-literal command |
| `python3 -c "os.remove(...)"` (inline code) | ✅ Blocked — gate can't inspect inline code |
| `curl http://example.com` (network) | ✅ Escalated for human approval |
| `curl ... \| bash` (piped execution) | ✅ Blocked — blocked tier overrides network |
| Recovery from vault | ✅ Files restored in seconds |

### Setup
```bash
# 1. Create test environment
cd integrations/claude_code
./test_setup.sh ~/agent-gate-test

# 2. Add hooks to ~/.claude/settings.json (see settings_example.json)

# 3. Launch Claude Code
cd ~/agent-gate-test/workspace && claude --dangerously-skip-permissions
```

See [integrations/claude_code/README.md](integrations/claude_code/README.md) for full setup and configuration.

### Vault Versioning

Every destructive action creates a timestamped snapshot. Multiple overwrites of the same file create multiple snapshots — full point-in-time recovery:
```
vault/
├── 20260215_142645/         ← first deletion
│   └── .../temp_logs/
│       ├── access.log
│       └── debug.log
├── 20260215_143446/         ← directory deletion
│   └── .../family_photos/
│       ├── kids_birthday.jpg
│       └── vacation_2024.jpg
├── 20260215_144423/         ← first overwrite
│   └── .../project_notes.md
└── 20260215_144712/         ← second overwrite
    └── .../project_notes.md (different content)
```

Recovery is a copy: `cp vault/<timestamp>/path/to/file workspace/path/to/file`

### Known Limitations — Honest Assessment

This is a safety net for well-intentioned agents making mistakes. It is not a security boundary against adversarial agents.

- **Literal-only enforcement** catches shell expansion syntax (`$VAR`, `$(cmd)`, backticks, globs, brace expansion) and interpreter inline code (`python3 -c`, `bash -c`), but programs can compute behavior internally without shell expansion — `python3 script.py` where the script contains `os.remove()` is literal to the gate but computed inside Python. Full coverage requires OS-level sandboxing.
- **Compound command splitting** is regex-based (`&&`, `||`, `;`, `|`) — nested or quoted delimiters may split incorrectly
- **Path extraction** treats all non-flag arguments as potential paths — conservative but naive
- This is application-layer gating, not OS-level sandboxing
- The gate trusts that Claude Code routes all tool calls through the hook system

## Quick Start
```bash
git clone https://github.com/SeanFDZ/agent-gate.git
cd agent-gate
pip3 install pyyaml
export PYTHONPATH=$(pwd):$PYTHONPATH

# Run the test suite
python3 -m tests.test_gate

# Use the rollback CLI
python3 -m agent_gate.cli list
python3 -m agent_gate.cli history /path/to/file
python3 -m agent_gate.cli restore <vault_path>
python3 -m agent_gate.cli diff <vault_path>
```

## Policy Definition

Policies are declarative YAML. Define once at design time, enforce at runtime:
```yaml
envelope:
  allowed_paths:
    - "${WORKDIR}/**"
  denied_paths:
    - "${HOME}/.ssh/**"
    - "${HOME}/.config/agent-gate/vault/**"

vault:
  path: "${HOME}/.config/agent-gate/vault"
  on_failure: "deny"  # No backup = no destruction

actions:
  destructive:
    patterns:
      - command: "rm"
      - command: "mv"
      - command: "sed"
        args_contain: ["-i"]
  blocked:
    patterns:
      - command: "rm"
        args_contain: ["-rf /"]
```

See [policies/default.yaml](policies/default.yaml) for the full default policy.

## The Nuclear C2 Analogy

This architecture is inspired by Permissive Action Links (PALs) in nuclear command and control. PALs don't evaluate whether a launch is wise — they verify that correct authority codes are present. Agent Gate follows the same principle:

- **Don't evaluate the agent's reasoning. Verify the action's authorization.**
- **The gate must not prevent authorized actions.** A gate that's too restrictive is as dangerous as one that's too permissive.
- **The backup vault is like the safing mechanism.** It doesn't prevent the action — it ensures the action is reversible.

## Architecture
```
agent_gate/
├── gate.py           # Gate core — intercept, classify, route, decide
├── classifier.py     # 5-tier classification, literal-only enforcement, symlink-resolved envelope
├── vault.py          # Vault manager — backup before destruction
├── policy_loader.py  # YAML policy parser and validator
└── cli.py            # Human-facing rollback interface
integrations/
└── claude_code/      # Claude Code PreToolUse hook integration
    ├── agent_gate_hook.py       # Bash tool hook
    ├── agent_gate_hook_write.py # Write/Edit tool hook
    ├── settings_example.json    # Hook configuration
    └── test_setup.sh            # Test environment setup
```

## Roadmap

- **Phase 1** ✅ — Core gate with simulated tool calls (48/48 tests passing)
- **Phase 2** ✅ — Claude Code integration via PreToolUse hooks (live tested)
- **Phase 2.5** ✅ — Hardening: symlink resolution, network tier, literal-only enforcement, policy conditions
- **Phase 3** — MCP proxy (transparent protocol-level interception)
- **Phase 4** — OPA/Rego policy engine (sub-millisecond evaluation at scale)

## The Gap This Fills

| Category | Examples | What They Solve | What They Don't |
|----------|----------|----------------|-----------------|
| Content guardrails | NeMo, LlamaGuard | What the LLM *says* | What the agent *does* |
| Agent sandboxes | nono, cco, Claude sandbox | Directory scoping | Pre-backup on destruction |
| Checkpoint tools | ccundo, git stash | Rollback | Agent can delete backups |
| **Agent Gate** | — | **Scoping + vault backup + agent-unreachable recovery** | — |

## License

Apache 2.0

## Author

Sean Lavigne — [GitHub](https://github.com/SeanFDZ)