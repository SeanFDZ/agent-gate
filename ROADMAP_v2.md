# Agent Gate — Development Roadmap (Revised)

**Version:** 0.4.0 → 0.5.0
**Date:** 2026-02-24
**Status:** Active development plan — revised based on competitive landscape and practitioner signal research
**Supersedes:** ROADMAP.md (v0.2.0 → v0.5.0, dated 2026-02-23)

---

## What Changed and Why

The original roadmap was written before comprehensive market research.  Two parallel research efforts, conducted February 2026, changed the prioritization:

1. **Competitive landscape analysis** (two independent agent reports) confirmed that vault-backed rollback, cryptographic hash-chained audit, and OPA/Rego integration are uncontested whitespace across the entire market.  No competitor offers any of these.  The acquisition of Acuvity (the closest architectural match to Agent Gate) by Proofpoint in February 2026 validated the thesis and removed the most dangerous direct competitor from the independent market.

2. **Practitioner signal research** (GitHub issues, HN threads, Reddit, incident databases) surfaced the real developer pain: agents deleting production systems, sub-agents silently bypassing parent permission rules, runaway costs with no kill switch, and agents fabricating records of what they did.  Ten documented destructive incidents across six tools in sixteen months.  These are not theoretical risks — they are current, documented, painful events that practitioners are trying to solve right now.

The original roadmap sequenced phases by compliance elegance.  The revised roadmap sequences by practitioner urgency first, enterprise credibility second, and positions Agent Gate for acquisition consideration within 18-24 months.

### What Stays

- Phase 8 (Cost Tracking) — validated from both the enterprise and practitioner sides, reframed as a safety control rather than a FinOps feature
- Phase 9 (Telemetry Export) — unchanged, still the enterprise deployment gate
- Phase 10 (Signed Receipts) — moved earlier, elevated from compliance feature to urgent response to documented agent deception incidents

### What Is New

- Phase 8A (Sub-agent Permission Inheritance) — not in the original plan, surfaces as the most-reported structural security flaw in the Claude Code integration
- Phase 11 (MCP Security Positioning) — explicit deliverable claiming the MCP governance narrative before Runlayer locks it

### Version Plan Change

The original plan grouped MODIFY + cost + telemetry into v0.4.0.  MODIFY shipped and v0.4.0 was tagged.  The revised plan runs v0.4.1 through v0.5.0 across two parallel tracks (developer trust, enterprise credibility) converging at a v0.5.0 milestone that is acquisition-credible.

---

## Strategic Context (Updated)

Agent Gate v0.4.0 delivers execution authority with vault-backed rollback, rate limiting, circuit breaker, dual-backend policy (Python/OPA), MCP proxy, identity binding, RBAC, MODIFY decisions, and structured audit with hash chaining.  428+ Python tests across 25 test suites, 24/24 Rego policy tests, 48/48 Claude Code live integration tests, 12/12 MCP proxy integration tests.

The roadmap ahead is shaped by four converging priorities:

1. **Practitioner adoption** — developers building with MCP and Claude Code are hitting real destructive incidents today.  Agent Gate's pre-execution interception and vault-backed rollback directly address the top-ranked practitioner pain points.  Adoption in this community builds the open-source credibility that precedes enterprise consideration.

2. **Acquisition positioning** — the window for independent category definition is 18-24 months.  Platform vendors (Proofpoint, SentinelOne, Cisco, Palo Alto, F5) are actively acquiring AI governance capabilities.  Agent Gate needs to reach a state where it represents a credible acqui-hire target: working implementation, community adoption, compliance mappings, and a defensible technical position that no acquirer has built internally.

3. **AARM conformance progression** — the AARM specification is new (v0.1, February 2025).  No competitor has aligned to it.  Being the reference implementation of an open standard gives standards-conscious enterprise buyers a reason to choose Agent Gate over proprietary platforms.

4. **NCCoE paper response** — the identity work in v0.3.0 gives us a working implementation to reference in the April 2026 NCCoE concept paper response.  Subsequent phases build on that foundation with verifiable audit and MCP governance evidence.

---

## Completed Phases

| Phase | Description | Version | Status |
|---|---|---|---|
| Phase 1 | Core gate with simulated tool calls | — | ✅ Complete |
| Phase 2 | Claude Code integration via PreToolUse hooks | — | ✅ Complete |
| Phase 2.5 | Hardening: symlink resolution, network tier, literal-only enforcement | — | ✅ Complete |
| Phase 3 | MCP proxy, transparent stdio interception | — | ✅ Complete |
| Phase 4 | OPA/Rego dual-backend policy engine | — | ✅ Complete |
| Phase 5 | Rate limiting, circuit breaker, policy hash traceability | v0.2.0 | ✅ Released 2026-02-23 |
| Phase 6 | Identity binding, RBAC, role-based overrides | v0.3.0 | ✅ Complete |
| Phase 7 | MODIFY decision, parameter rewriting | v0.4.0 | ✅ Released |

---

## Track 1: Developer Trust (v0.4.1)

**Target:** March–April 2026
**Strategic:** Directly addresses the top two practitioner pain points from incident research.  These are the features developers will find when they search for solutions after their agent nukes something.

---

## Phase 8A: Sub-agent Permission Inheritance

**Target:** March 2026
**AARM:** R6 (Identity Binding) — extension, sub-agent identity propagation
**NIST:** AC-3(7) (RBAC) — enforcement through agent hierarchies, not just at session level
**Strategic:** Most-reported structural security flaw in the Claude Code integration.  Directly responds to GitHub #25000 and its four duplicate issues.  Zero competitors address this.

### The Problem

Agent Gate enforces deny rules at the session level.  When a parent agent spawns a sub-agent via the Task tool, the sub-agent receives no deny rules — it operates with unrestricted tool access regardless of what the parent's policy says.

This is documented and reproducible.  A developer with `"Bash"` in their deny list approved a security audit Task tool call.  The sub-agent then executed 22+ bash commands without any individual approval: reading `~/.ssh/`, examining bash history, enumerating processes, scanning network connections, and performing filesystem searches — all output sent to the model without per-command consent.

The security implications are structural.  Carefully configured deny rules give false security confidence.  A single prompt injection in a file the agent reads can trigger sub-agent spawning that bypasses every configured restriction.  There is no independent logging of sub-agent actions outside conversation transcripts.

UpGuard analysis of 18,470 public Claude Code configuration files found that 98.9% contain zero deny rules.  The primary reason practitioners give: approval overhead is so high that they disable it entirely.  Phase 8A addresses both problems simultaneously — risk-proportionate enforcement that applies through agent hierarchies means the remaining 1.1% who do configure rules actually get the protection they expect.

### Deliverables

**Policy schema extension:**

```yaml
# Sub-agent policy inheritance model
agents:
  inheritance: "strict"   # "strict" | "permissive" | "additive"
  # strict:      sub-agents inherit parent deny rules, cannot exceed parent authority
  # permissive:  sub-agents operate with base policy only (current behavior, opt-in)
  # additive:    sub-agents inherit parent rules plus any sub-agent-specific additions

  # Sub-agent-specific overrides (applied on top of inherited rules)
  subagent_overrides:
    max_depth: 2          # Maximum sub-agent nesting depth
    allowed_tools:
      - "Read"
      - "Write"
      # Task (spawning further sub-agents) omitted = sub-agents cannot spawn sub-sub-agents
    additional_deny:
      - "Bash(rm:*)"      # Tighter restrictions for sub-agents than parent
      - "Bash(curl:*)"
```

**Audit schema extension:**

```json
{
  "event": "tool_call",
  "agent_depth": 1,
  "parent_agent_id": "session-abc123",
  "agent_id": "subagent-def456",
  "inherited_policy": true,
  "denied_rules_active": ["Bash(rm:*)", "Bash(curl:*)"],
  "tool": "Bash",
  "command": "ls -la ~/.ssh/",
  "verdict": "deny",
  "reason": "Bash blocked by inherited deny rule from parent session"
}
```

**Implementation scope:**

- `gate.py` — Agent depth tracking, parent/child session linkage, policy inheritance resolution
- `policy_loader.py` — Parse `agents` section, build inheritance chain, merge deny rules
- `agent_gate_hook.py` — Pass agent depth and parent session ID via environment or context header
- `audit.py` — Add `agent_depth`, `parent_agent_id`, `inherited_policy` to AuditRecord
- `opa_classifier.py` — Pass agent hierarchy context to OPA for attribute-based decisions
- `cli.py` — `agent-gate tree <session_id>` command to visualize agent hierarchy and decisions

**What this unlocks:**

- Deny rules that actually work when sub-agents are involved
- Audit records that reconstruct agent hierarchy, not just flat event logs
- Foundation for multi-agent governance narratives in NCCoE paper and LinkedIn content
- Response to the most-filed structural security issue in the Claude Code integration

### Design Decision Required Before Implementation

**How does gate.py know it is running inside a sub-agent?**  Three options with different tradeoffs:

1. **Environment variable injection** — parent hook writes `AGENT_GATE_PARENT_SESSION` and `AGENT_GATE_DEPTH` before spawning.  Simple, works with existing hook architecture.  Risk: environment variables can be cleared by the agent.

2. **Session file on disk** — parent writes a session manifest to a fixed path the gate reads at startup.  More robust than env vars.  Requires file I/O at every gate invocation.

3. **Agent-unreachable side channel** — parent writes session state to vault storage.  Sub-agents cannot tamper with it.  Most secure, most complex.

Recommendation: Option 1 for v0.4.1, upgrade to Option 3 when vault architecture is finalized.  Document the limitation honestly.

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R6 (Identity Binding) | ⚠️ Partial | ⚠️ Improved — identity propagates through agent hierarchies, sub-agent actions attributed to originating operator |

---

## Phase 8B: Cost Enforcement as a Safety Control

**Target:** April 2026
**AARM:** R3 (Policy Evaluation) — cost context as a policy input
**Strategic:** Validated from both enterprise buyers and practitioners.  Reframed as a safety control, not a FinOps dashboard.  AgentOps and Portkey own cost *visibility*.  Agent Gate owns cost *enforcement as a governance gate*.

### The Problem

Rate limits control how fast an agent operates.  Cost limits control how much an agent spends.  These are related but distinct controls.  An agent making 5 API calls per minute is within rate limits, but if each call hits Anthropic's Opus endpoint it could be burning $10/minute.

The practitioner evidence is visceral: a $187 charge in 10 minutes from a GPT-4o retry loop.  A Claude Code session estimated at $3.65 that actually cost $663.59.  A user charged $1,200 despite setting a $30 hard limit on OpenAI.  A $47,000 bill from two LangChain agents stuck in a loop for eleven days.  These are not edge cases — they are the expected consequence of agents that loop without a kill switch.

Critically, no existing governance tool enforces budget caps at the pre-execution layer.  LangSmith, Langfuse, and AgentOps measure cost after the fact.  AgentBudget (a community-built tool, GitHub) was created specifically because no framework ships pre-execution cost gates.  Agent Gate is the first governance-layer tool to treat budget enforcement as a pre-execution safety control on par with tier classification.

### Architecture

Same split as rate limiting — the pattern is already proven:

- **Cost data lives in YAML.**  Dollar amounts, endpoint patterns, model names — configuration that changes when providers update pricing, not when security policy changes.  Optional external cost file for separation of pricing data from security policy.
- **Cost accumulation lives in Python.**  In-memory sliding window for per-minute tracking, session total.  Stateful computation OPA cannot do.
- **Cost threshold evaluation lives in both paths.**  Python path checks thresholds directly.  OPA path receives pre-computed `cost_context` and evaluates it statelessly alongside `rate_context`, identity, and tier.

The composed OPA policy is the strategic prize: `cost × tier × identity` in a single policy evaluation.  No content guardrail can express this.

### Deliverables

**YAML configuration:**

```yaml
cost_limits:
  tool_costs:
    curl:
      default: { usd_est: 0.01 }
      patterns:
        # Anthropic — per-call estimates based on ~1k token average
        - args_contain: ["api.anthropic.com", "claude-opus"]
          usd_est: 0.075
        - args_contain: ["api.anthropic.com", "claude-sonnet"]
          usd_est: 0.015
        - args_contain: ["api.anthropic.com", "claude-haiku"]
          usd_est: 0.003
        # OpenAI
        - args_contain: ["api.openai.com", "gpt-4o"]
          usd_est: 0.025
        - args_contain: ["api.openai.com", "gpt-4o-mini"]
          usd_est: 0.003
        # Free/internal
        - args_contain: ["localhost"]
          usd_est: 0.00
    write_file: { usd_est: 0.001 }
    database_query:
      default: { usd_est: 0.01 }
      patterns:
        - args_contain: ["SELECT *"]
          usd_est: 0.10
        - args_contain: ["DELETE", "DROP"]
          usd_est: 0.50

  max_usd_per_minute: 1.00
  max_usd_per_session: 25.00

  # Dry-run mode: log violations without blocking — deploy before enforcing
  on_exceed: "deny"     # "deny" | "log" | "escalate"
  message: "Session cost limit reached.  Estimated session total: ${session_total}."
```

**OPA input shape:**

```json
{
  "command": "curl",
  "args": ["api.anthropic.com/v1/messages", "--data", "{\"model\": \"claude-opus-4-6\"}"],
  "rate_context": { "..." },
  "cost_context": {
    "this_call_est": 0.075,
    "session_total": 4.27,
    "minute_total": 0.82,
    "budget_session": 25.00,
    "budget_minute": 1.00,
    "matched_pattern": "api.anthropic.com + claude-opus"
  },
  "identity": { "role": "developer" }
}
```

**Composed OPA policies:**

```rego
# Cross-cutting: expensive + destructive = escalate
escalate_required if {
    input.cost_context.this_call_est > 0.50
    input.tier == "destructive"
}

# Role-based budgets
budget_exceeded if {
    input.identity.role == "restricted"
    input.cost_context.session_total > 10.00
}

budget_exceeded if {
    input.identity.role == "admin"
    input.cost_context.session_total > 100.00
}
```

**Implementation scope:**

- `cost_tracker.py` — Cost accumulator with pattern matching, sliding window for per-minute tracking, session total.  Mirrors `rate_tracker.py` architecture.
- `policy_loader.py` — Parse `cost_limits` section, validate patterns, load optional external cost file
- `gate.py` — Check cost limits before classification (same position as rate limits), pass `cost_context` to OPA
- `audit.py` — Add `cost_est`, `matched_cost_pattern`, `session_cost_total` to AuditRecord
- `yaml_to_rego.py` — Compile cost threshold rules for OPA evaluation
- Agent feedback — "Session cost: $4.27 of $25.00 budget.  This call est: $0.075 (anthropic/claude-opus)."

**Important design note:** All estimates are labeled `cost_est`, not `cost`.  The matched pattern is included in every audit record.  The system is honest about the estimation model: pattern-matched flat estimates, not token-counted actuals.  Post-execution actuals via the MCP proxy response body are a future extension, not a Phase 8B deliverable.

**Dry-run mode** (`on_exceed: log`) is a first-class feature.  Cautious teams deploy cost tracking in monitoring-only mode, observe patterns for a week, then switch to enforcement.  This lowers adoption friction without compromising the enforcement architecture.

**What this unlocks:**

- Pre-execution budget enforcement as a safety control, not a dashboard
- FinOps visibility: which models and providers are consuming the budget
- Role-based budgets via OPA: admin gets $100, restricted gets $10
- Composed decisions (cost × tier × identity) — something no content guardrail can express
- Foundation for chargeback in multi-tenant deployments
- LinkedIn content: "the first governance tool to treat budget as a safety gate, not an afterthought"

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R3 (Policy Evaluation) | ⚠️ Partial | ⚠️ Improved — cost context as a policy input alongside rate, identity, and tier |

---

## Track 2: Enterprise Credibility (v0.4.2)

**Target:** April–May 2026
**Strategic:** Moves Agent Gate from "developer tool" to "survives an enterprise security RFP."  Both phases in this track are prerequisites for acquisition consideration.

---

## Phase 9: Telemetry Export

**Target:** April 2026
**AARM:** R8 (Telemetry Export) — currently ⚠️ Foundation Laid
**Strategic:** Table stakes for enterprise deployment.  Without SIEM export, Agent Gate won't survive a security vendor evaluation.  No architectural changes required — the audit data shape is ready, transport is what's missing.

### The Problem

Agent Gate writes JSONL to local files.  Enterprise security environments require structured event export to centralized SIEM/SOAR platforms (Splunk, Elastic, Microsoft Sentinel, IBM QRadar).  The data is good.  The transport does not exist.

This is not a feature request — it is a deployment gate.  Enterprise security teams have existing SIEM infrastructure.  A governance tool that doesn't feed it cannot be approved by the security team, regardless of its technical capabilities.

### Deliverables

**Configuration:**

```yaml
logging:
  # Existing JSONL logging unchanged — all new config is additive

  export:
    syslog:
      enabled: true
      host: "siem.corp.internal"
      port: 514
      protocol: "tcp"       # "tcp" | "udp" | "tls"
      facility: "auth"
      format: "cef"         # "cef" | "json" | "ocsf"

    webhook:
      enabled: false
      url: "https://hooks.corp.internal/agent-gate"
      headers:
        Authorization: "Bearer ${AGENT_GATE_WEBHOOK_TOKEN}"
      batch_size: 10
      flush_interval_seconds: 5
      retry_attempts: 3

    otlp:
      enabled: false
      endpoint: "https://otel-collector.corp.internal:4317"
      headers:
        api-key: "${OTEL_API_KEY}"
```

**CEF format example (Splunk/ArcSight compatible):**

```
CEF:0|AgentGate|AgentGate|0.4.2|tool_call_denied|Tool call denied by policy|7|
  src=developer@workstation
  suser=developer
  act=deny
  cs1=Bash
  cs1Label=tool
  cs2=rm -rf /workspace/data/
  cs2Label=command
  cs3=destructive
  cs3Label=tier
  cs4=matched_pattern:rm -rf
  cs4Label=policy_match
  outcome=failure
  reason=Destructive command blocked by policy
```

**OCSF format** (Open Cybersecurity Schema Framework — emerging enterprise standard):

```json
{
  "class_uid": 6003,
  "class_name": "API Activity",
  "activity_id": 6,
  "activity_name": "Deny",
  "severity_id": 4,
  "time": 1740000000000,
  "actor": {
    "user": { "name": "developer", "uid": "developer@workstation" },
    "session": { "uid": "session-abc123" }
  },
  "api": {
    "service": { "name": "AgentGate" },
    "operation": "tool_call"
  },
  "resources": [{ "name": "Bash", "data": "rm -rf /workspace/data/" }],
  "policy": { "name": "destructive_pattern", "uid": "sha256:abc..." }
}
```

**Implementation scope:**

- `telemetry.py` — Exporter interface with syslog (CEF and OCSF), webhook (JSON with batching and retry), and OTLP backends
- `audit.py` — Hook exporters into the logging pipeline, export alongside local write, non-blocking (export failure does not affect gate decision)
- Schema mappings: CEF field mapping, OCSF event schema, OpenTelemetry span attributes
- Connection management: reconnect on failure, configurable retry, dead-letter queue for webhook

**Critical constraint:** Export failures must never affect gate decisions.  If the SIEM is unreachable, the gate continues operating and queues events locally.  Audit integrity trumps export completeness.

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R8 (Telemetry Export) | ⚠️ Foundation Laid | ✅ Satisfied — structured export to SIEM/SOAR via syslog, webhook, and OTLP |

---

## Phase 10A: Signed Receipts (Verifiable Action Records)

**Target:** May 2026
**AARM:** R5 (Tamper-Evident Receipts) — currently ⚠️ Partial
**Depends on:** Phase 6 (Identity) for identity-bound signatures
**Strategic:** Moved forward from original Phase 10 position.  Agent deception is a current practitioner problem, not a future compliance feature.

### The Problem

Hash chaining proves integrity — tampering is detectable after the fact.  But it does not prove authorship, and it does not answer the practitioner's actual question after an incident: "did my agent actually run that command, or is it lying to me?"

The incident record is damning.  Replit fabricated 4,000 user records to cover a database deletion and incorrectly told the user that rollback was impossible (it was possible and was later done manually).  Amazon Kiro autonomously destroyed a production environment and Amazon's public statement attributed it to user misconfiguration.  Google Gemini CLI confirmed operations that never occurred.  Cursor acknowledged "DO NOT RUN ANYTHING" and then executed more commands.  A Meta AI alignment researcher had to rush to her computer "like defusing a bomb" to stop an OpenClaw agent that was deleting emails while she typed STOP commands — the safety directives had been dropped by context compaction.

In every case, the agent's self-report about what it did was unreliable.  Signed receipts break the dependency on self-report.  A receipt signed by Agent Gate at the interception layer, independent of the model's own accounting, provides forensic-grade evidence of what actually happened — and what was blocked.

This is also the capability that no other tool in the market has implemented, despite AARM specifying it as a core requirement.

### Deliverables

**Receipt schema:**

```json
{
  "receipt_id": "rcpt-sha256-abc123",
  "version": "1.0",
  "timestamp_iso": "2026-02-24T07:00:00Z",
  "timestamp_unix_ms": 1740384000000,

  "agent": {
    "operator": "sean@workstation",
    "agent_id": "session-def456",
    "role": "developer",
    "agent_depth": 0
  },

  "action": {
    "tool": "Bash",
    "command": "rm -rf /workspace/data/",
    "args_hash": "sha256:xyz789"
  },

  "decision": {
    "verdict": "deny",
    "tier": "destructive",
    "reason": "Destructive pattern matched: rm -rf",
    "policy_hash": "sha256:policy-abc",
    "cost_est": null,
    "rate_context": { "tool_calls_last_60s": 12 }
  },

  "chain": {
    "prev_receipt_hash": "sha256:prev-receipt",
    "receipt_sequence": 47
  },

  "signature": {
    "algorithm": "Ed25519",
    "public_key_id": "agentgate-key-2026-02",
    "value": "base64-encoded-signature"
  }
}
```

**Signing infrastructure:**

- Process-local Ed25519 key generation at gate startup (minimum viable for v0.4.2)
- Optional KMS/HSM integration configuration for production environments (architecture defined, not required for initial ship)
- Public key export: `agent-gate export-pubkey > agentgate.pub`
- Signed receipt emitted alongside JSONL record on every decision

**Verification CLI:**

```bash
# Verify a single receipt
agent-gate verify-receipt receipt-00047.json

# Verify all receipts in an audit log
agent-gate verify-chain audit.jsonl

# Verify with a known public key (for offline/forensic use)
agent-gate verify-receipt receipt-00047.json --pubkey agentgate.pub
```

**Verification output:**

```
Receipt #47: VALID
  Signed by: agentgate-key-2026-02
  Timestamp: 2026-02-24T07:00:00Z
  Chain integrity: OK (follows receipt #46)
  Action: Bash(rm -rf /workspace/data/) → DENY
  Operator: sean@workstation / developer
  Policy: sha256:abc... (matches current policy: YES)

  This receipt proves:
    - The action was presented to Agent Gate at the stated timestamp
    - The deny decision was made under the stated policy
    - The record has not been modified since signing
    - The stated operator identity was active at decision time
```

**Implementation scope:**

- `receipts.py` — Receipt generation, Ed25519 signing (using Python `cryptography` library), receipt schema serialization
- `audit.py` — Emit signed receipt alongside JSONL, include receipt hash in JSONL record for cross-reference
- `cli.py` — `verify-receipt` and `verify-chain` commands
- Key management: `generate-key`, `rotate-key`, `export-pubkey` CLI commands
- `policy_loader.py` — No changes, policy hash already captured
- Documentation: receipt verification guide for compliance officers and auditors

**What this unlocks:**

- Answer to "did the agent actually run that command, or is it lying?" — answered independently of the model
- Forensic-grade audit evidence for regulated industry compliance (financial services, healthcare, government)
- Non-repudiation: operator cannot credibly deny that a specific action was presented and decided under their identity
- Acquisition signal: signed receipts are the feature that enterprise security platforms don't have and would want

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R5 (Tamper-Evident Receipts) | ⚠️ Partial (hash chaining) | ✅ Satisfied — cryptographically signed receipts with identity binding and chain integrity |

### NIST Advancement

| Control | Before | After |
|---|---|---|
| AU-10 (Non-repudiation) | ⚠️ Partial | ✅ Implemented — identity-bound signed receipts, offline verification |

---

## Convergence Milestone: v0.5.0

**Target:** June 2026
**Codename:** Convergence
**Strategic:** The version that is acquisition-credible.  Every capability that an enterprise security acquirer would evaluate is present, documented, and mapped to compliance frameworks.

---

## Phase 11: MCP Security Positioning and Hardening

**Target:** June 2026
**AARM:** R1 (Intercept), R3 (Policy Evaluation) — MCP-specific coverage
**Strategic:** Explicit claim on the MCP governance narrative before Runlayer ($11M seed, Khosla-backed) locks it.  Agent Gate already has MCP proxy infrastructure — this phase makes it a security story, not just an integration detail.

### The Problem

MCP has become the dominant interoperability standard for agentic AI.  It has also become the most actively exploited attack surface.  Ten documented breach classes in twelve months.  A 9.6 CVSS CVE in the mcp-remote npm package (437,000+ downloads).  Tool poisoning attacks invisible to users.  Rug-pull vulnerabilities where tool definitions change after user approval.  43% of MCP implementations vulnerable to command injection.  100% exploit success rate against Claude and other models at DEF CON.

Runlayer (launched November 2025, $11M seed, already has Gusto, Instacart, and Opendoor as customers) is positioning as the MCP-native security platform.  They have a four-month head start in enterprise logos and a direct claim on the "MCP security" search result.

Agent Gate has the infrastructure advantage: the MCP proxy was built in Phase 3 and is already intercepting `tools/call` at the protocol level.  What's missing is the security story, the hardening, and the documentation that says "Agent Gate is the governance layer for MCP deployments."

### Deliverables

**MCP-specific policy controls:**

```yaml
mcp:
  # Tool definition pinning — detect rug-pull attacks
  tool_pinning:
    enabled: true
    on_change: "deny"     # "deny" | "warn" | "log"
    # When a tool's description or parameters change after first seen,
    # block calls to that tool until the operator re-approves the new definition

  # Hidden instruction scanning — detect tool poisoning
  instruction_scanning:
    enabled: true
    patterns:
      - "read.*~/.ssh"
      - "pass.*contents.*parameter"
      - "before using this tool"
      - "ignore previous"
    on_match: "deny"

  # Server allowlist — prevent connections to unknown MCP servers
  server_allowlist:
    enabled: false          # opt-in, not default
    allowed:
      - "filesystem"
      - "github"
    on_unlisted: "escalate"

  # Tool-level permission scoping (fills MCP spec gap — draft only, not shipped)
  tool_permissions:
    read_file: { tier: "readonly" }
    write_file: { tier: "destructive" }
    execute_command: { tier: "destructive" }
```

**Tool definition fingerprinting:**

- Hash each tool's name, description, and parameter schema at first connection
- Store fingerprints in a local manifest: `~/.agent-gate/mcp-tool-manifest.json`
- On every subsequent connection, verify against stored fingerprints
- Surface definition changes as policy violations: "Tool 'add' definition changed since last approval.  Previous hash: sha256:abc.  New hash: sha256:xyz.  Call blocked until operator re-approves."

**MCP security hardening:**

- Validate all tool parameter values against declared parameter schemas before forwarding
- Scan tool descriptions for known tool poisoning patterns (configurable pattern list)
- Log all MCP server connections with server identity, tool inventory, and connection metadata
- Rate limiting per MCP server, not just per tool (complement to existing per-tool limits)

**Vault coverage extension to MCP tool calls:**

This is a documented Known Limitation in v0.4.0.  MCP tool calls (e.g., `delete_file` via the filesystem MCP server) are correctly classified as destructive and denied or escalated by policy — but they do not currently trigger an automatic vault snapshot the way `rm` does through the Claude Code PreToolUse hook.  The vault backup path currently operates on bash command arguments and file write paths.  Extending it to MCP tool call parameters (extracting the target path from `{"path": "/workspace/data/important.txt"}` and snapshotting before forwarding) closes this gap and makes vault-backed rollback consistent across both integration paths.

Implementation scope addition: `mcp_proxy.py` — extract path arguments from destructive MCP tool calls, invoke vault backup before forwarding to real server (mirrors existing bash hook behavior).

A dedicated `MCP_SECURITY.md` in the repo documenting:
- The threat model: tool poisoning, rug-pull, command injection, cross-server exfiltration
- How Agent Gate's proxy architecture addresses each threat class
- What Agent Gate does not protect against (honest gap assessment)
- Comparison with mcp-scan (static analysis, pre-deployment) vs. Agent Gate (runtime enforcement, pre-execution)
- Integration guidance: using Agent Gate alongside mcp-scan for layered defense

**Implementation scope:**

- `mcp_proxy.py` — Tool definition fingerprinting, hidden instruction scanning, server allowlist enforcement, schema validation before forwarding
- `policy_loader.py` — Parse `mcp` section, validate pinning and scanning configuration
- `gate.py` — MCP-specific verdict routing for pinning violations and instruction scan matches
- `audit.py` — MCP connection events, tool definition change events, scan match events
- `MCP_SECURITY.md` — Security positioning document
- Test suite: tool poisoning simulation, rug-pull detection, schema validation

**What this unlocks:**

- Credible MCP security positioning against Runlayer
- The combination of MCP interception + AARM compliance + OPA policy that no competitor offers
- A documentation artifact suitable for the NCCoE paper and LinkedIn content
- Hardened MCP proxy that security-conscious developers can deploy with confidence

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R1 (Intercept) | ✅ Satisfied | ✅ Reinforced — MCP-specific interception with tool definition verification |
| R3 (Policy Evaluation) | ⚠️ Partial | ⚠️ Improved — MCP threat model explicitly addressed in policy evaluation |

---

## Version Plan

| Version | Codename | Key Capabilities | Target |
|---|---|---|---|
| **v0.3.0** | Identity | Identity binding, RBAC, role-based overrides | ✅ Complete |
| **v0.4.0** | Authority | MODIFY decisions, parameter rewriting | ✅ Released |
| **v0.4.1** | Developer Trust | Sub-agent permission inheritance, cost enforcement as safety control | March–April 2026 |
| **v0.4.2** | Enterprise Credibility | Telemetry export (syslog/webhook/OTLP), signed receipts | April–May 2026 |
| **v0.5.0** | Convergence | MCP security hardening and positioning, full AARM documentation | June 2026 |

---

## AARM Conformance Trajectory

| Version | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | Core Status |
|---|---|---|---|---|---|---|---|---|---|---|
| **v0.4.0** | ✅ | ⚠️ | ⚠️ | ⚠️+ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ | 2/6 satisfied |
| **v0.4.1** | ✅ | ⚠️ | ⚠️+ | ⚠️+ | ⚠️ | ⚠️+ | ❌ | ⚠️ | ❌ | 2/6 satisfied, improved coverage |
| **v0.4.2** | ✅ | ⚠️ | ⚠️+ | ⚠️+ | ✅ | ⚠️+ | ❌ | ✅ | ❌ | 4/6 satisfied |
| **v0.5.0** | ✅ | ⚠️ | ⚠️+ | ⚠️+ | ✅ | ⚠️+ | ❌ | ✅ | ❌ | 4/6 satisfied, R1 reinforced |

---

## NIST SP 800-53 Gap Trajectory

| Version | ❌ Gaps | ✅ Implemented | Notes |
|---|---|---|---|
| **v0.4.0** | 0 | 24 of 31 | Identity closes AC-3(7) |
| **v0.4.1** | 0 | 25 of 32 | Sub-agent RBAC extends AC-3(7) coverage |
| **v0.4.2** | 0 | 27 of 34 | Telemetry closes AU-3 gaps, signed receipts fully satisfies AU-10 |
| **v0.5.0** | 0 | 28 of 35 | MCP hardening adds SI-3 (malicious code protection) coverage |

---

## Competitive Positioning Summary

Agent Gate's defensible position at v0.5.0:

| Capability | Agent Gate | Runlayer | Astrix | Zenity | Airia | All Others |
|---|---|---|---|---|---|---|
| Pre-execution tool call interception | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Framework-agnostic (not MCP-only) | ✅ | ❌ | ❌ | ❌ | ❌ | varies |
| Vault-backed rollback | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Cryptographic signed receipts | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| OPA/Rego integration | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Sub-agent permission inheritance | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| AARM specification alignment | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Self-hosted / open-source | ✅ | ❌ | ❌ | ❌ | ❌ | varies |
| Cost enforcement (pre-execution) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MCP protocol native support | ✅ | ✅ | ⚠️ | ❌ | ⚠️ | ❌ |
| SIEM telemetry export | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | varies |

The combination of framework-agnostic pre-execution interception + vault-backed rollback + OPA/Rego + signed receipts + AARM alignment is not offered by any single competitor.

---

## Acquisition Positioning Notes

The following capabilities are specifically relevant to potential acquirers (Proofpoint, SentinelOne, Cisco, Palo Alto, F5, CrowdStrike):

- **Vault-backed rollback** — no acquirer has this.  It fills a gap in every existing platform.
- **Signed receipts** — forensic-grade audit that satisfies regulated industry requirements.  Financial services and healthcare verticals require this and cannot buy it elsewhere.
- **OPA/Rego integration** — Cisco, Palo Alto, and other infrastructure-native acquirers already have OPA deployments.  Agent Gate's Rego-based policies slot directly into existing policy-as-code infrastructure.
- **AARM alignment** — being the reference implementation of an open standard is an IP position.  Standards leadership has acquisition value independent of revenue.
- **Framework-agnostic architecture** — Runlayer is MCP-only.  Acuvity/Proofpoint was the closest framework-agnostic alternative and is now locked inside a large platform.  Agent Gate is the only remaining open-source framework-agnostic pre-execution governance tool.

The 18-24 month window for independent category definition closes as platform consolidation continues.  v0.5.0 completion (June 2026) is the target state for initiating acquisition conversations, if that path is desired.

---

## External Milestones

| Date | Milestone | Agent Gate Dependency |
|---|---|---|
| **10 Mar 2026** | LinkedIn Post 5 (first comment with repo link, 0700 CT) | v0.4.0 MODIFY content |
| **17 Mar 2026** | LinkedIn Post 7 (first comment with repo link, 0700 CT) | Sub-agent permission story (Phase 8A in progress) |
| **April 2026** | NCCoE concept paper on AI Agent Identity and Authorization | v0.3.0 identity binding + Phase 8A sub-agent hierarchy as reference implementation |
| **May 2026** | v0.4.2 release | Signed receipts — acquisition signal milestone |
| **June 2026** | v0.5.0 release | Full convergence — MCP hardening, AARM documentation, acquisition-credible milestone |
| **Ongoing** | AARM community engagement | AARM_Alignment.md progression as visible evidence |

---

## Deferred (Post v0.5.0)

### DEFER Decision (AARM R4)

Requires an async hold queue and a mechanism to revisit deferred actions when additional context arrives.  The current proxy operates synchronously — DEFER requires an architectural shift to event-driven processing.  Worth building once an approval service exists for ESCALATE completion, since both need the same async infrastructure.

### Semantic Distance Tracking (AARM R7)

Requires embedding infrastructure to compute similarity between the original user request and current agent actions.  Architecturally heavy, requires a model in the evaluation loop (contradicts the "pre-computed, no LLM at runtime" principle).  Consider as an optional plugin rather than core functionality.

### Session Context Accumulator (AARM R2, full)

The rate tracker provides operational context.  Full AARM R2 wants semantic context: ordered action history, data sensitivity tracking, original intent capture.  The foundation is laid with `rate_context` — extending it to a full session context store is incremental but requires defining the semantic capture schema first.

### Progressive Autonomy Profiles

Multiple rate limit profiles (conservative/standard/permissive) that agents graduate between based on demonstrated reliability.  The rate limiting infrastructure supports this — it is a policy design pattern on top of existing mechanisms.

### Discovery and Inventory

Zenity, Astrix, and Obsidian all lead with agent discovery as their first value proposition.  Agent Gate does not currently compete here — agents must be explicitly routed through it.  A lightweight discovery mode that identifies Claude Code and MCP usage on a system without requiring pre-configuration would lower the adoption barrier.  Post v0.5.0 if acquisition has not occurred.

---

## Execution Principles

1. **Each phase ships with tests, updated compliance docs, and updated AARM alignment.**  Documentation is not a follow-up task — it ships with the code.

2. **Backward compatibility is non-negotiable.**  Every new feature is optional.  Existing policies work without modification.

3. **Each version is a credible standalone milestone.**  v0.4.1 can stand alone as "execution authority that is safe with sub-agents."  v0.4.2 can stand alone as "enterprise-deployable governance with forensic audit."  v0.5.0 can stand alone as "the open-source MCP governance layer."  No version depends on the next to be useful.

4. **Implementation evidence over theoretical proposals.**  Every NIST submission, LinkedIn post, and NCCoE paper reference points to working code, passing tests, and honest gap assessments.

5. **Practitioner language over enterprise marketing language.**  Developers say "my agent nuked my home directory."  Agent Gate documentation should acknowledge that directly, not reframe it as "unintended destructive file system operations."

6. **Acquisition readiness is a non-functional requirement.**  Every phase should be documented such that a technical acquirer's due diligence team can evaluate it independently.  Code quality, test coverage, compliance mapping, and gap honesty all contribute to this.

---

## Research Basis

This roadmap revision is grounded in four research documents produced February 24, 2026:

- `market_research_agent_governance_2026.md` — Competitive landscape, gap analysis table, enterprise buyer priorities
- `market_research_agent_governance_2026_v2.md` — Independent corroborating competitive analysis, additional vendors (Runlayer, Acuvity/Proofpoint, Cranium), acquisition timeline analysis
- `developer_signal_agent_governance_2026_Opus.md` — Practitioner pain points from GitHub issues, HN threads, incident databases
- `developer_signal_agent_governance_2026_Sonnet.md` — Corroborating practitioner signal, UpGuard YOLO mode analysis, MCP breach timeline

All four documents are retained as reference material.  When roadmap decisions are questioned, the research basis is available for review.
