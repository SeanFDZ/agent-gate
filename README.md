# Agent Gate

**Execution authority layer for AI agents - vault-backed rollback and policy enforcement.**

Agent Gate sits between an AI agent's proposed tool calls and their execution.  It inspects every action as structured data, classifies it against pre-computed policy, enforces directory boundaries, binds identity to every decision, controls operational tempo, rewrites unsafe parameters to policy-compliant forms, and automatically backs up targets to an agent-unreachable vault before any destructive operation proceeds.

The agent runs at full autonomy and full speed.  The gate silently ensures every destructive action is reversible, every action stays within the authorized envelope, every decision is identity-attributed, and no runaway loop overwhelms the systems the agent operates on.

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
   │ 1. Identity │  ← resolve operator, agent, role from env/config
   │ 2. Literal? │  ← reject shell expansion ($VAR, $(cmd), globs)
   │ 3. Tempo?   │  ← circuit breaker open? rate limit exceeded?
   │ 4. Classify │  ← "rm" = destructive action
   │ 5. Envelope │  ← is resolved path authorized? (follows symlinks)
   │ 6. Modify?  │  ← rewrite args to safe form (if modify rule)
   │ 7. Vault    │  ← copy important.txt to vault
   │ 8. Allow    │  ← backup confirmed, proceed
   └─────────────┘
         │
         ▼
   rm important.txt executes (or modified form)
```

Identity is resolved once at gate initialization from environment variables, policy configuration, or MCP metadata.  The operator, agent, service account, and role are bound to every decision and every audit record, so the full chain of "who asked, through what agent, under what role, what happened" is captured without any per-call overhead.

If the command contains shell expansion syntax, it's rejected before classification — the gate can't trust extracted paths when the shell would transform the command.  The agent is told to rewrite using literal values.

If rate limits are exceeded or the circuit breaker has tripped, the action is denied before classification even runs — the gate stops runaway loops at the earliest possible point.

If the backup fails, the destructive action is blocked.  No snapshot, no destruction.

The vault lives outside the agent's permitted directory envelope. The same gate that enforces the envelope protects the vault. The agent cannot reach, modify, or delete the backups.

## Design Principles

1. **Prevention over auditability.**  Audit trails are necessary but not sufficient.  The architecture makes damage reversible, not just logged.
2. **Pre-computed classification, not runtime evaluation.**  Risk tiers and rules are defined at design time.  The runtime check is a lookup, not an LLM call.
3. **Inspect the action, not the reasoning.**  We don't need to understand why an agent wants to delete a file.  We see "rm" targeting a path and match it against policy.
4. **Literal-only enforcement.**  The gate defines what "clean" looks like, literal paths, flags, and simple values, and rejects anything else.  Shell expansion syntax (`$VAR`, `$(cmd)`, globs, backticks) is denied before classification because the gate can't trust paths it can't read.  This is an allowlist on arguments, not a blocklist on shell tricks.
5. **Operational envelope, not just authority envelope.**  Authorization answers "can this agent do this?"  Rate limiting answers "can this agent do this *right now*, given operational context?"  An agent operating within its authority can still cause a production incident by executing allowed operations too rapidly.
6. **Identity binding, not identity verification.**  Agent Gate doesn't authenticate users — it binds whatever identity context is present (operator, agent, service account, role) to every decision and audit record.  Authentication happens upstream.  The gate ensures that identity flows through the entire enforcement pipeline and that role-based overrides are applied consistently.
7. **Tiered response.**  Auto-allow safe actions, vault-backup destructive ones, rewrite unsafe parameters to compliant forms, escalate network access, hard-stop prohibited ones.
8. **Structured denial feedback.**  The gate doesn't just say "no."  It returns why, what would be required to proceed, and how much budget remains.
9. **Policy traceability.**  Every audit record includes a cryptographic hash of the governing policy, proving which exact policy version made each decision.

## Tiered Classification

| Tier | Examples | Gate Behavior |
|------|----------|---------------|
| **Read-only** | `cat`, `ls`, `grep`, `find` | Auto-allow within envelope |
| **Destructive** | `rm`, `mv`, `sed -i`, overwrite | Backup to vault, then allow |
| **Network** | `curl`, `wget`, `ssh`, `scp` | Escalate for human approval (configurable) |
| **Blocked** | `rm -rf /`, `curl \| bash`, `mkfs` | Hard deny with feedback |
| **Unclassified** | Anything not in policy | Default deny, request human review |
| **Rate-limited** | Any tool exceeding tempo limits | Deny with remaining budget, reset timing, and recovery path |

### Verdict Decisions

| Verdict | Meaning | Example |
|---|---|---|
| ALLOW | Action permitted, proceed | `cat file.txt` |
| DENY | Action blocked | `rm -rf /` |
| ESCALATE | Requires human approval | `curl https://api.example.com` |
| MODIFY | Action rewritten to safe form | `chmod 777` -> `chmod 755` |

## Rate Limiting & Circuit Breaker

Agent Gate treats agents as distributed systems that need operational tempo controls, not just action authorization.  An agent operating entirely within its authority envelope can still cause a production incident by executing allowed operations too rapidly, such as a tight loop of file deletions that overwhelms a filesystem or a burst of API calls that triggers upstream throttling.

Rate limiting is fully optional.  If the `rate_limits` section is absent from the policy YAML, all rate checking is skipped and the gate behaves exactly as before.

### Three Layers of Rate Control

**Per-tool limits** — each tool has its own sliding window counter.  `rm` at 10/minute is independent from `cat` at 120/minute.

**Per-tier defaults** — aggregate limits across all tools in a classification tier.  If no tool-specific limit exists, the tier default applies.  This catches novel tools that aren't individually configured.

**Global limit** — all tool calls combined.  A hard ceiling on total operational tempo regardless of which tools are being used.

```yaml
rate_limits:
  tools:
    rm:
      max_calls: 10
      window_seconds: 60
      on_exceed: "deny"
    cat:
      max_calls: 120
      window_seconds: 60

  tier_defaults:
    read_only:  { max_calls: 120, window_seconds: 60 }
    destructive: { max_calls: 30, window_seconds: 60, on_exceed: "escalate" }

  global:
    max_calls: 200
    window_seconds: 60
    on_exceed: "read_only"
```

### Circuit Breaker

A three-state circuit breaker (CLOSED → OPEN → HALF_OPEN → CLOSED) monitors derivative metrics across all tool calls.  If the failure rate exceeds the configured threshold, the breaker trips and restricts the agent to read-only operations until automatic recovery probes succeed.

```
CLOSED:    Normal operation.  Track outcomes.
OPEN:      Failure rate exceeded threshold.  Non-read actions denied.
HALF_OPEN: After wait duration, allow limited probe calls.
           Success → CLOSED.  Failure → back to OPEN.
```

The HALF_OPEN state provides automatic recovery without human intervention, following the same pattern used by Resilience4j, Hystrix, and every production circuit breaker implementation.

### Agent Feedback on Rate Denial

When a rate limit is exceeded, the agent receives actionable information to self-regulate:

```
ACTION DENIED: rm rate limit exceeded.  Max 10 calls per 60s.
DETAILS: 11 calls in the last 60 seconds (limit: 10).
RATE STATUS: tool_remaining=0, global_remaining=113, breaker=closed
TO PROCEED: Wait 12 seconds for the window to clear, or reduce operation frequency.
```

This follows the same principle as API rate limit headers (X-RateLimit-Remaining, X-RateLimit-Reset), giving the agent enough context to adjust its behavior without human intervention.

### Exponential Backoff

Repeated rate limit violations trigger exponential backoff (5s → 10s → 20s → 40s, capped at 5 minutes).  This prevents tight retry loops from becoming a denial-of-service vector against the systems the agent operates on.  A successful call within limits resets the backoff multiplier.

## Identity Binding & RBAC

Agent Gate binds identity context to every gate decision, implementing four of the five AARM R6 identity levels.  Identity is resolved once at gate initialization from environment variables or policy configuration, then propagated through the entire enforcement pipeline: gate decisions, audit records, and OPA policy input.

### Five Identity Levels

| AARM Level | Agent Gate Field | Source |
|---|---|---|
| Human identity | `operator` | `AGENT_GATE_OPERATOR` env var or config |
| Service identity | `service_account` | `AGENT_GATE_SERVICE` env var or config |
| Agent identity | `agent_id` | `AGENT_GATE_AGENT_ID` env var or config |
| Session identity | `session_id` | Auto-generated UUID per session |
| Role/privilege scope | `role` | `AGENT_GATE_ROLE` env var or config → RBAC |

Identity resolution supports `${VAR}` environment variable expansion in policy fields, so the same policy file works across environments without modification.

### Role-Based Policy Overrides

Roles modify the base policy without replacing it.  An `admin` role can raise rate limits and allow network access while a `restricted` role can tighten limits and block access to configuration directories, all from the same policy file:

```yaml
identity:
  source: "environment"
  fields:
    operator: "${AGENT_GATE_OPERATOR}"
    agent_id: "${AGENT_GATE_AGENT_ID}"
    service_account: "${AGENT_GATE_SERVICE}"
    role: "${AGENT_GATE_ROLE}"

  roles:
    admin:
      rate_limits:
        global: { max_calls: 500, window_seconds: 60 }
      actions:
        network:
          behavior: "allow"
    restricted:
      rate_limits:
        global: { max_calls: 50, window_seconds: 60 }
      envelope:
        denied_paths_append:
          - "${WORKDIR}/config/**"
```

Role overrides are applied via deep merge, meaning a role's rate limit overrides extend the base policy rather than replacing it.  Tool-specific limits that the role doesn't mention remain in effect.

### Identity in Audit Records

Every audit record includes the identity fields that were present at the time of the decision.  These fields are automatically included in the SHA-256 hash chain, so tampering with identity attribution breaks the chain the same way tampering with any other field would.

```json
{"timestamp":"2026-02-23T15:30:00Z","tool_name":"rm","arguments":{"command":"rm temp.log"},"verdict":"allow","tier":"destructive","operator":"sean","agent_id":"claude-code-1","role":"admin","prev_hash":"b4c8...","record_hash":"d9e2..."}
```

### Identity in OPA/Rego

When using the OPA backend, identity is passed as `input.identity` in the OPA input document.  The YAML-to-Rego compiler generates RBAC helper rules (`role_has_override`, `role_behavior`, `role_rate_limit`) and role-specific test scaffolds automatically.

Identity binding is fully optional and backward-compatible.  Policies without an `identity` section work identically to v0.2.0.

## MODIFY Verdict (v0.4.0)

The gate can rewrite tool call parameters to make them policy-compliant rather than blocking them outright.  Examples:

- `chmod 777 deploy.sh` -> `chmod 755 deploy.sh` (permission clamped)
- `rm -rf /workspace/data/` -> `rm -r /workspace/data/` (force flag stripped)

Five modify operations are supported: `clamp_permission`, `strip_flags`, `require_flags`, `append_arg`, `max_depth`.  All operations are idempotent and fail closed.

The proxy owns the reinvocation loop: after modification, the gate re-evaluates the modified call.  One combined audit record captures both original and modified parameters.

## Policy Backends

Agent Gate supports two policy evaluation backends. The gate architecture (vault, routing, condition evaluation, denial feedback) is identical regardless of backend — only the classification engine differs.

### Python Backend (default, zero dependencies)

Policies defined in YAML, evaluated as pure Python pattern matching. No external services required. Works everywhere Python runs.

```python
gate = Gate(policy_path="policies/default.yaml", workdir="/path/to/project")
```

Best for: individual developers, Claude Code integration, simple deployments.

### OPA/Rego Backend (enterprise scale)

Policies defined in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), evaluated by [Open Policy Agent](https://www.openpolicyagent.org/). Adds policy composition, attribute-based decisions, formal policy testing, and integration with existing governance toolchains (Kubernetes, API gateways, data filtering).

```python
gate = Gate(
    policy_path="policies/default.yaml",
    workdir="/path/to/project",
    classifier_backend="opa",
    opa_config={
        "mode": "subprocess",       # or "http" for OPA sidecar
        "policy_path": "./rego/",   # directory containing .rego files
        "package": "agent_gate",    # Rego package name
    }
)
```

Or declare the backend in the policy YAML itself:
```yaml
classifier:
  backend: "opa"
  opa:
    mode: "subprocess"
    policy_path: "./rego/"
    package: "agent_gate"
```

Best for: enterprise deployments, teams needing RBAC/policy composition, identity-scoped policy decisions, organizations already using OPA.

**Why OPA?**

- **Policy composition** — base policy + team overlay + project overlay + temporary JIT grants, composed into a single decision
- **Attribute-based decisions** — who's requesting, what time, what environment, not just what command
- **Formal policy testing** — unit tests written in Rego, run with `opa test ./rego/ -v`
- **Enterprise ecosystem** — drops into existing Kubernetes admission control, API authorization, and data filtering toolchains

**OPA quick start:**
```bash
# Install OPA
brew install opa  # macOS
# or: curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x opa

# Run Rego policy tests (includes rate limit threshold tests)
opa test ./rego/ -v
```

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

## MCP Proxy (Protocol-Level Interception)

Agent Gate includes a transparent MCP proxy that sits between any MCP client and server, intercepting `tools/call` requests and routing them through `Gate.evaluate()` before forwarding to the real server. Neither side knows the gate is there.

```
LLM Client (Claude Desktop, Claude Code, etc.)
    │
    │  MCP JSON-RPC (stdio)
    ▼
┌──────────────┐
│  AGENT GATE  │
│  MCP PROXY   │
├──────────────┤
│ Intercept    │ ← receive tools/call from client
│ Translate    │ ← map MCP params to Gate.evaluate() format
│ Gate         │ ← classify, envelope, vault, decide
│ Route        │ ← ALLOW → forward to real server
│              │   DENY → return JSON-RPC error to client
│              │   ESCALATE → hold for human approval
│              │   MODIFY → rewrite args, re-evaluate, then route
└──────────────┘
    │
    │  MCP JSON-RPC (stdio)
    ▼
Real MCP Server (filesystem, database, API, etc.)
```

### Usage

```bash
# Wrap any MCP server with Agent Gate
python -m agent_gate.mcp_proxy -- npx @modelcontextprotocol/server-filesystem /path/to/project

# With explicit policy and name
AGENT_GATE_POLICY=./policies/default.yaml \
python -m agent_gate.mcp_proxy --name my-fs-server -- npx @modelcontextprotocol/server-filesystem /path
```

### Claude Desktop Configuration

Replace the server command in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python3",
      "args": [
        "-m", "agent_gate.mcp_proxy",
        "--name", "filesystem",
        "--",
        "npx", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"
      ],
      "env": {
        "AGENT_GATE_POLICY": "/Users/you/agent-gate/policies/default.yaml",
        "AGENT_GATE_WORKDIR": "/Users/you/projects",
        "PYTHONPATH": "/Users/you/agent-gate"
      }
    }
  }
}
```

The client sees the same tools, same capabilities, same protocol. The proxy silently enforces the policy underneath.

### What Gets Intercepted

| MCP Message | Proxy Behavior |
|-------------|----------------|
| `initialize` | Pass through (handshake) |
| `tools/list` | Pass through (tool discovery) |
| `tools/call` | **Intercept → Gate.evaluate() → allow/deny/escalate/modify** |
| `resources/*` | Pass through |
| `prompts/*` | Pass through |
| Everything else | Pass through |

### Denial Response

When the gate denies a tool call, the client receives a standard JSON-RPC error with Agent Gate metadata:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32001,
    "message": "Agent Gate: action denied — Target path(s) outside authorized envelope.",
    "data": {
      "gate_verdict": "deny",
      "tier": "blocked",
      "reason": "Target path(s) outside authorized envelope."
    }
  }
}
```

The agent sees the denial reason and can adjust its approach — exactly like a PAL rejection tells the operator what authority is missing.

### Structured Audit Log

Every tool call through the proxy is logged to a JSONL audit file with SHA-256 hash chaining for tamper evidence.  Each record includes a `prev_hash` linking to the prior record and a `record_hash` of its own content, creating a cryptographic chain from a deterministic genesis value.  Any modification, insertion, or deletion of a historical record breaks the chain from that point forward.

Each record also includes a `policy_hash`, a truncated SHA-256 hash of the governing policy bundle.  This proves which exact policy version made each decision, so modifying the policy after the fact cannot disguise the original authorization logic.  Rate-limited decisions additionally include a `rate_context` snapshot capturing the rate tracking state at the moment of decision.

```json
{"timestamp":"2026-02-23T15:30:00Z","tool_name":"rm","arguments":{"command":"rm temp.log"},"verdict":"deny","tier":"rate_limited","reason":"rm rate limit exceeded.  Max 10 calls per 60s.","policy_hash":"a3f7b2c9e1d045f8","rate_context":{"tool_counts":{"rm":{"count":11,"limit":10}},"global_count":{"count":87,"limit":200},"breaker_state":"closed"},"prev_hash":"b4c8...","record_hash":"d9e2..."}
```

A `verify_chain()` function walks the log and confirms integrity in a single pass — any tampered or deleted record is detected immediately.

### Configuration

The proxy uses tiered configuration (env vars > config file > defaults):

```bash
# Simple: env vars only
export AGENT_GATE_POLICY=./policies/default.yaml
export AGENT_GATE_WORKDIR=/path/to/project

# Advanced: config file at ~/.config/agent-gate/proxy.yaml
```

```yaml
# ~/.config/agent-gate/proxy.yaml
policy: ./policies/default.yaml
workdir: /path/to/project
classifier_backend: opa
audit_log: ~/.config/agent-gate/audit.jsonl
opa:
  mode: http
  endpoint: ${AGENT_GATE_OPA_URL}
  package: agent_gate
  filter_tools_list: true
```

### Integration Test Results (12/12 passing — Feb 19, 2026)

Tested against the real `@modelcontextprotocol/server-filesystem`:

| Scenario | Result |
|----------|--------|
| MCP initialize handshake | ✅ Passed through, protocol negotiated |
| tools/list discovery | ✅ All 14 tools visible to client |
| read_file (read-only) | ✅ Evaluated by gate, forwarded to server |
| list_directory (unclassified) | ✅ Gate denied (unclassified → deny by policy) |
| Audit log captures all decisions | ✅ JSONL with timing, tier, verdict |
| Gate evaluation timing | ✅ Sub-millisecond (avg 0.8ms) |
| Proxy startup and clean shutdown | ✅ Server subprocess managed |

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

### Known Limitations - Honest Assessment

This is a safety net for well-intentioned agents making mistakes.  It is not a security boundary against adversarial agents.

- **Application-layer gating, not OS-level sandboxing.**  Agent Gate operates at the tool call level — it inspects what the agent asks to do, not what programs do internally once executed.  If your policy allows `python3` (or any interpreter) and the script contains `os.remove()`, the gate sees a literal command and allows it.  The default policy classifies unknown commands (including `python3`) as unclassified and denies them — so this is a policy choice, not a gate bypass.  Full internal-execution coverage requires OS-level sandboxing (containers, seccomp, AppArmor), which is complementary to Agent Gate, not replaced by it.
- **Path extraction** treats all non-flag arguments as potential paths — conservative but naive.  This errs on the side of safety (more things are checked against the envelope than necessary) but may produce false positives for commands with non-path arguments.
- **Rate limiting state is in-memory.**  Counters and circuit breaker state reset when the gate process restarts.  This is acceptable for single-agent sessions but means rate limits don't persist across restarts.  For long-running multi-agent deployments, a shared state backend (Redis, etc.) would be needed.
- **Identity binding, not identity verification.**  Agent Gate binds identity context from environment variables and configuration but does not authenticate against an external identity provider.  It implements four of five AARM R6 identity levels — external IdP integration (the fifth level) is a roadmap item.  Authentication is expected to happen upstream of the gate.
- **Vault backup is not yet wired for MCP tool calls.**  The MCP proxy classifies tool calls and enforces envelope boundaries, but the vault's pre-destruction backup currently operates on bash commands and file write paths.  An MCP `delete_file` call will be correctly classified as destructive and denied or escalated by policy — but it won't trigger an automatic vault snapshot the way `rm` does through the Claude Code hook.  Extending vault coverage to MCP tool arguments is a future item.

## Quick Start
```bash
git clone https://github.com/SeanFDZ/agent-gate.git
cd agent-gate
pip3 install pyyaml
export PYTHONPATH=$(pwd):$PYTHONPATH

# Run all test suites (428+ Python tests)
python3 -m pytest tests/ -v

# Run OPA policy tests (24/24 Rego tests, requires opa binary)
opa test ./rego/ -v

# Run live integration test (12/12, requires npx + @modelcontextprotocol/server-filesystem)
python3 tests/test_integration_mcp.py

# Use the rollback CLI
python3 -m agent_gate.cli list
python3 -m agent_gate.cli history /path/to/file
python3 -m agent_gate.cli restore <vault_path>
python3 -m agent_gate.cli diff <vault_path>
```

## Policy Definition

### YAML (Python backend)

Policies are declarative YAML.  Define once at design time, enforce at runtime:
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

# Optional — omit entirely to disable rate limiting
rate_limits:
  tools:
    rm:  { max_calls: 10, window_seconds: 60, on_exceed: "deny" }
    cat: { max_calls: 120, window_seconds: 60 }
  tier_defaults:
    destructive: { max_calls: 30, window_seconds: 60, on_exceed: "escalate" }
  global: { max_calls: 200, window_seconds: 60, on_exceed: "read_only" }
  circuit_breaker:
    enabled: true
    failure_rate_threshold: 0.50
    wait_duration_open_seconds: 30

# Optional — omit entirely for uniform policy (no identity/RBAC)
# See "Identity Binding & RBAC" section above for full schema
identity:
  source: "environment"
  fields:
    operator: "${AGENT_GATE_OPERATOR}"
    role: "${AGENT_GATE_ROLE}"
  roles:
    admin:
      rate_limits:
        global: { max_calls: 500, window_seconds: 60 }
      actions:
        network: { behavior: "allow" }
```

See [policies/default.yaml](policies/default.yaml) for the full default policy.

### Rego (OPA backend)

Same semantics expressed in OPA's policy language:
```rego
package agent_gate

destructive_patterns := {
    "rm": {"command": "rm", "description": "File deletion"},
    "mv": {"command": "mv", "description": "Move/rename"},
    "write_file": {
        "command": "write_file",
        "condition": "target_exists",
        "description": "Overwrite existing file",
    },
}

blocked_patterns := {
    "rm_rf_root": {
        "command": "rm",
        "args_contain": ["-rf /"],
        "description": "Recursive force delete at root",
    },
}
```

See [rego/agent_gate.rego](rego/agent_gate.rego) for the full Rego policy.  The YAML-to-Rego compiler (`yaml_to_rego.py`) generates equivalent Rego from your YAML policy, including rate limit threshold rules when `rate_limits` is configured and RBAC identity rules when `identity.roles` is configured.  Run `opa test ./rego/ -v` to execute the policy unit tests.

## The Nuclear C2 Analogy

This architecture is inspired by Permissive Action Links (PALs) in nuclear command and control.  PALs don't evaluate whether a launch is wise — they verify that correct authority codes are present.  Agent Gate follows the same principle:

- **Don't evaluate the agent's reasoning.  Verify the action's authorization.**
- **The gate must not prevent authorized actions.**  A gate that's too restrictive is as dangerous as one that's too permissive.
- **The backup vault is like the safing mechanism.**  It doesn't prevent the action — it ensures the action is reversible.
- **Nuclear launch sequences have timing constraints and sequencing requirements separate from authorization codes.**  Rate limiting and circuit breakers enforce the operational envelope, the same way launch procedures enforce cadence independently of authority.
- **Nuclear authority is always attributed — every command in the chain knows who issued it.**  Identity binding ensures every gate decision records the operator, agent, and role, creating the same end-to-end attribution chain.

## Architecture
```
agent_gate/
├── gate.py              # Gate core — intercept, classify, route, decide
├── identity.py          # Identity resolver — AARM R6 identity levels, env/config resolution
├── modifier.py          # Modify operations — clamp_permission, strip_flags, require_flags, append_arg, max_depth
├── classifier_base.py   # Abstract classifier with shared pre-processing
├── classifier.py        # Python backend — YAML policies, pure Python eval
├── opa_classifier.py    # OPA backend — Rego policies via subprocess or HTTP
├── vault.py             # Vault manager — backup before destruction
├── policy_loader.py     # YAML policy parser, validator, identity/role config, modify rules, and policy hash
├── rate_tracker.py      # Sliding window counters, circuit breaker, backoff
├── cli.py               # Human-facing rollback interface
├── mcp_proxy.py         # MCP proxy — transparent stdio interception layer with modify reinvocation
├── mcp_jsonrpc.py       # JSON-RPC 2.0 parser for MCP protocol messages
├── proxy_config.py      # Proxy configuration loader (env/file/defaults)
├── audit.py             # Structured JSONL audit logger with hash chaining, policy hash, identity, and modify records
└── yaml_to_rego.py      # YAML-to-Rego compiler (rate limits + RBAC identity + modify rules)
rego/
├── agent_gate.rego      # OPA policy (equivalent to default.yaml)
└── agent_gate_test.rego # Formal policy unit tests
integrations/
└── claude_code/         # Claude Code PreToolUse hook integration
    ├── agent_gate_hook.py       # Bash tool hook (with identity resolution)
    ├── agent_gate_hook_write.py # Write/Edit tool hook (with identity resolution)
    ├── settings_example.json    # Hook configuration
    └── test_setup.sh            # Test environment setup
tests/
├── test_gate.py                   # Core gate tests
├── test_gate_identity.py          # Identity propagation and role override tests
├── test_gate_rates.py             # Rate limiting integration tests
├── test_gate_feedback.py          # Rate-limited agent feedback tests
├── test_identity.py               # Identity resolver unit tests
├── test_rate_tracker.py           # Sliding window counter and circuit breaker tests
├── test_policy_loader_rates.py    # Rate limits schema validation tests
├── test_policy_loader_identity.py # Identity section and role override validation tests
├── test_audit.py                  # Audit logger tests
├── test_audit_hash.py             # Policy hash and rate context audit tests
├── test_audit_identity.py         # Identity fields in audit records tests
├── test_opa_identity.py           # OPA identity input and RBAC Rego generation tests
├── test_mcp_jsonrpc.py            # JSON-RPC parser tests
├── test_proxy_config.py           # Config loader tests
├── test_mcp_proxy.py              # MCP proxy unit tests
├── test_mcp_proxy_identity.py     # MCP proxy identity resolution tests
├── test_modifier.py               # Modify operations unit tests
├── test_policy_loader_modify.py   # Modify policy parsing and validation tests
├── test_classifier_modify.py      # Classifier modify/args_match tests
├── test_gate_modify.py            # Gate MODIFY verdict and vault skip tests
├── test_audit_modify.py           # Audit MODIFY record field tests
├── test_opa_modify.py             # OPA modifications rule and Rego compiler tests
├── test_mcp_proxy_modify.py       # MCP proxy reinvocation loop tests
└── test_integration_mcp.py        # Live integration tests
```

### Gate Evaluation Pipeline

```
Identity Resolution (once at init)
  │
  ├── Resolve operator, agent_id, service_account, role
  ├── Apply role-based rate limit overrides (deep merge)
  ├── Apply role-based gate behavior overrides
  │
  ▼
Tool Call → Rate Check (O(1) counter lookup, role-adjusted limits)
              │
              ├── Circuit breaker OPEN? → DENY
              ├── Tool rate exceeded? → DENY/ESCALATE
              ├── Global rate exceeded? → DENY/ESCALATE
              │
              └── ClassifierBase (shared pre-processing)
                    │
                    ├── Parse command + args
                    ├── Shell expansion detection (block non-literal)
                    ├── Path extraction (resolve symlinks)
                    │
                    ├── Tier rate check (post-classification)
                    │
                    └── _evaluate() → backend-specific
                          │
                          ├── PythonClassifier: YAML patterns, fnmatch envelope
                          └── OPAClassifier: Rego evaluation via subprocess/HTTP
                                              (input.identity for RBAC decisions)
              │
              ▼
        GateDecision (includes identity context for audit binding)
              │
              ├── MODIFY? → modifier.py rewrites args → re-evaluate
              │              (proxy owns reinvocation loop, depth cap = 1)
```

Identity resolution happens once at gate initialization, not per-call.  Rate checks happen before classification because they're O(1) counter comparisons, not policy evaluation.  A rate-tripped agent is stopped at the earliest possible point.  Pre-processing is structural and backend-independent.  Envelope checking and tier matching are policy decisions — this is what the backend implements.

## Roadmap

- **Phase 1** ✅ — Core gate with simulated tool calls
- **Phase 2** ✅ — Claude Code integration via PreToolUse hooks (live tested)
- **Phase 2.5** ✅ — Hardening: symlink resolution, network tier, literal-only enforcement, policy conditions
- **Phase 3** ✅ — MCP proxy (transparent stdio proxy intercepting `tools/call`, live integration tests with filesystem MCP server)
- **Phase 4** ✅ — OPA/Rego policy engine (dual-backend classifier, formal Rego policy tests)
- **Phase 5** ✅ — Rate limiting & circuit breaker (sliding window counters, three-state circuit breaker, per-tool/per-tier/global limits, exponential backoff, policy hash traceability in audit records, Rego compiler support)
- **Phase 6** ✅ — Identity binding & RBAC (AARM R6 identity levels, environment/config resolution, role-based rate limit and gate behavior overrides, identity-attributed audit records, OPA/Rego RBAC rules, MCP proxy identity propagation)
- **Phase 7** ✅ — MODIFY verdict (parameter rewriting to safe form, five modify operations, reinvocation loop, pattern-level vault skip, args_match regex, combined audit records, OPA modifications rule)

## The Gap This Fills

| Category | Examples | What They Solve | What They Don't |
|----------|----------|----------------|-----------------|
| Content guardrails | NeMo, LlamaGuard, Guardrails AI | What the LLM *says* (hallucinations, PII, toxicity) | What the agent *does* |
| Agent orchestration platforms | Airia, Astrix ACP | Fleet management, routing, cost optimization, governance dashboards | Pre-execution authority on individual tool calls |
| Agent sandboxes | nono, cco, Claude sandbox | Directory scoping | Pre-backup on destruction |
| Checkpoint tools | ccundo, git stash | Rollback after the fact | Agent can delete its own backups |
| **Agent Gate** | — | **Pre-execution authority + identity-attributed decisions + RBAC role overrides + vault backup + rate limiting + circuit breaker + MODIFY parameter rewriting + agent-unreachable recovery + policy-as-code (YAML or OPA/Rego) + policy-hash audit traceability** | — |

**Why not just use Airia or Guardrails AI?**  They solve different problems.  Guardrails AI validates what an LLM *outputs* (content safety, PII filtering, hallucination detection) — it assumes the agent is already authorized to act.  Airia is an enterprise orchestration platform — it manages which agents run, routes requests between models, and provides governance dashboards.  Neither inspects individual tool calls against risk tiers before execution, neither provides vault-backed rollback that the agent can't reach, neither enforces operational tempo limits to prevent runaway loops, and neither binds identity context to every authorization decision for end-to-end attribution.  Agent Gate is the enforcement layer that sits inside the execution pipeline, not above it.

## License

Apache 2.0

## Author

Sean Lavigne — [GitHub](https://github.com/SeanFDZ)

---

Agent Gate's enforcement pattern maps to NIST SP 800-53 AC-3 (Access Enforcement),
AC-3(7) (Role-Based Access Control), AU-9 (Protection of Audit Information),
AU-10 (Non-repudiation), AU-12 (Audit Generation), CM-3 (Configuration Change Control),
CP-9 (System Backup), IA-2 (Identification and Authentication), IA-4 (Identifier Management),
SC-5 (Denial-of-Service Protection), SI-4 (System Monitoring), SI-10 (Information Input
Validation), SI-17 (Fail-Safe Procedures), and NIST AI RMF MG-2.4 (Contain AI System
Impact), GOVERN 1.7 (Operational Risk Management), and MEASURE 2.6 (Performance Monitoring).