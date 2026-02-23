# Agent Gate — Development Roadmap

**Version:** 0.3.0 → 0.5.0
**Date:** 2026-02-23
**Status:** Active development plan

---

## Strategic Context

Agent Gate v0.3.0 delivers execution authority with vault-backed rollback, rate limiting, circuit breaker, identity binding with RBAC, dual-backend policy (Python/OPA), MCP proxy, and structured audit with hash chaining, policy hash traceability, and identity binding.  310+ tests across seventeen suites.

The roadmap ahead is shaped by three converging priorities:

1. **NCCoE concept paper on AI Agent Identity and Authorization (due April 2026)** — the identity work below gives us a working implementation to reference, not a theoretical proposal.
2. **AARM conformance progression** — closing the remaining AARM Core gaps (R4, R6) positions Agent Gate as one of the few public implementations building toward the specification.
3. **Enterprise adoption path** — identity, MODIFY decisions, cost tracking, and telemetry export are the features that move Agent Gate from "developer tool" to "enterprise-deployable."

---

## Phase 6: Identity Binding (v0.3.0) ✅ Implemented

**Target:** March 2026 — ✅ Released 2026-02-23
**AARM:** R6 (Identity Binding) — ❌ Gap → ⚠️ Partial
**NIST:** AC-3(7) (RBAC) — ❌ Gap → ✅ Implemented
**Strategic:** Prerequisite for NCCoE paper response.  Unlocks multi-agent differentiation.

### What Was Delivered

- `identity.py` — `IdentityContext` frozen dataclass with `resolve_identity()` for environment/config-based identity resolution
- `policy_loader.py` — `identity` section parsing with role-based overrides for rate limits, gate behavior, and envelope
- `gate.py` — Identity propagated through evaluation pipeline; role overrides applied at initialization
- `audit.py` — `operator`, `agent_id`, `service_account`, `role` fields on every AuditRecord, included in record hash
- `opa_classifier.py` — `input.identity` in OPA input for attribute-based decisions
- `yaml_to_rego.py` — RBAC Rego rules auto-generated from role definitions
- `mcp_proxy.py` — Identity resolved at proxy startup, propagated to gate and audit
- 93 new tests across 6 test suites (313 total, up from 220)

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R6 (Identity Binding) | ❌ Gap | ⚠️ Partial — environment/config-based identity at 4 of 5 levels (operator, service, agent, session; role via RBAC) |

### NIST Advancement

| Control | Before | After |
|---|---|---|
| AC-3(7) (RBAC) | ❌ Gap | ✅ Implemented — role-based policy differentiation |
| AU-10 (Non-repudiation) | ⚠️ Partial | ⚠️ Improved — identity binding in audit records (still needs signing) |
| IA-2 (Identification) | — | ⚠️ Partial — environment/config-based identity |
| IA-4 (Identifier Management) | — | ⚠️ Partial — session, operator, agent, service identifiers |

---

## Phase 7: MODIFY Decision (v0.3.0 or v0.4.0)

**Target:** March–April 2026
**AARM:** R4 (Five Authorization Decisions) — currently ⚠️ Partial
**Strategic:** Differentiator against sandbox tools that can only block.

### The Problem

Agent Gate currently makes binary decisions: allow or deny.  ESCALATE exists but effectively converts to deny without an approval service.  There is no mechanism to rewrite a tool call to make it safe rather than blocking it outright.

Examples of where MODIFY adds value:

- Agent tries `SELECT * FROM users` → gate rewrites to `SELECT * FROM users LIMIT 100`
- Agent tries `rm -rf /workspace/data/` → gate rewrites to `rm -rf /workspace/data/tmp/` (scope reduction)
- Agent tries `curl http://api.example.com` → gate rewrites to add `--max-time 30` (timeout enforcement)
- Agent tries `chmod 777 deploy.sh` → gate rewrites to `chmod 755 deploy.sh` (permission clamping)

### Deliverables

**New verdict:**

```python
class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    MODIFY = "modify"       # NEW
```

**Policy schema extension:**

```yaml
actions:
  destructive:
    patterns:
      - command: "rm"
        args_contain: ["-rf"]
        modify:
          # Rewrite rules applied before forwarding
          strip_args: ["-f"]              # Remove force flag
          max_depth: 2                    # Limit recursive depth
          require_args: ["--interactive"] # Add safety flag
      - command: "chmod"
        modify:
          clamp_permissions: "755"        # Maximum permission value
```

**Implementation scope:**

- `gate.py` — Add `Verdict.MODIFY`, implement `_handle_modify()` that rewrites tool call parameters
- `classifier_base.py` — `ClassificationResult` carries modification rules when matched
- `mcp_proxy.py` — Forward modified parameters to server instead of original
- `audit.py` — Log both original and modified parameters for forensic trail
- Agent feedback — Tell the agent what was modified and why

**What this unlocks:**

- "Allow with guardrails" posture instead of binary allow/deny
- Safer agent autonomy — more actions can proceed (modified) rather than being blocked
- Competitive differentiator against every tool that only does allow/block

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R4 (Five Decisions) | ⚠️ Partial (ALLOW, DENY, ESCALATE) | ⚠️ Improved (ALLOW, DENY, ESCALATE, MODIFY; still missing DEFER) |

---

## Phase 8: Cost Tracking (v0.4.0)

**Target:** April 2026
**Strategic:** Enterprise adoption feature.  Natural extension of rate limiting infrastructure.

### The Problem

Rate limits control how fast an agent operates.  Cost limits control how much an agent spends.  An agent making 5 API calls per minute is within rate limits, but if each call costs $2, the session is burning $10/minute.  Organizations need budget caps alongside tempo controls.

The challenge is that costs vary dramatically even within a single tool.  A `curl` to a free public API costs nothing.  A `curl` to Anthropic's API costs anywhere from $0.0008/1k tokens (Haiku input) to $0.075/1k tokens (Opus output) — nearly 100x difference depending on model selection.  A flat per-tool estimate is better than nothing, but provider- and model-aware estimation is what enterprises actually need.

### Architecture

Same split as rate limiting:

- **Cost data lives in YAML.**  Dollar amounts, endpoint patterns, model names — that's configuration that changes when providers update pricing, not when security policy changes.
- **Cost accumulation lives in Python.**  In-memory tracking of cumulative spend, same sliding window pattern as rate counters.  Stateful computation that OPA can't do.
- **Cost threshold evaluation lives in both paths.**  Python path checks thresholds directly.  OPA path receives a pre-computed `cost_context` and evaluates it statelessly alongside rate_context, identity, and tier — enabling composed decisions like "expensive + destructive + restricted role = escalate."

### Deliverables

**Tier 1 (ship first): Pattern-based cost estimation with provider/model awareness.**

```yaml
cost_limits:
  # Per-tool cost estimates with provider/model patterns
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

  # Budget caps
  max_usd_per_minute: 1.00
  max_usd_per_session: 25.00
  on_exceed: "deny"
  message: "Session cost limit exceeded."
```

The `args_contain` list uses AND logic — all strings must appear in the arguments.  `"api.anthropic.com"` matches the URL, `"claude-sonnet"` matches the model substring in the payload.  Same pattern-matching infrastructure the classifier already uses.  Substring matching means `claude-sonnet` catches `claude-sonnet-4-5-20250929` and any future Sonnet version.

**Tier 2 (fast follow): External cost file.**

Pricing changes more frequently than security policy.  An operator might update Anthropic's rates monthly without touching the authority envelope.

```yaml
# In default.yaml
cost_limits:
  cost_file: "costs/provider_rates.yaml"   # External file, optional
  max_usd_per_minute: 1.00
  max_usd_per_session: 25.00
```

```yaml
# In costs/provider_rates.yaml — separate file, separate update cycle
providers:
  anthropic:
    endpoint: "api.anthropic.com"
    models:
      claude-opus:   { usd_per_1k_input: 0.015, usd_per_1k_output: 0.075 }
      claude-sonnet: { usd_per_1k_input: 0.003, usd_per_1k_output: 0.015 }
      claude-haiku:  { usd_per_1k_input: 0.0008, usd_per_1k_output: 0.004 }
  openai:
    endpoint: "api.openai.com"
    models:
      gpt-4o:      { usd_per_1k_input: 0.005, usd_per_1k_output: 0.015 }
      gpt-4o-mini: { usd_per_1k_input: 0.00015, usd_per_1k_output: 0.0006 }
```

**Tier 3 (future): Response-based cost capture.**

After tool execution, capture actual cost from response headers (e.g., OpenAI returns token counts).  Feed real cost back into the accumulator.  Requires post-execution hooks, which Agent Gate doesn't have yet — the gate currently operates pre-execution only.  This is a future architectural addition.

**OPA input shape:**

```json
{
  "command": "curl",
  "args": ["api.anthropic.com", "claude-opus-4-6"],
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

This enables composed OPA policies:

```rego
# Role-based budgets
budget_exceeded if {
    input.identity.role == "restricted"
    input.cost_context.session_total > 10.00
}

budget_exceeded if {
    input.identity.role == "admin"
    input.cost_context.session_total > 100.00
}

# Cross-cutting: expensive + destructive = escalate
escalate_required if {
    input.cost_context.this_call_est > 0.50
    input.tier == "destructive"
}
```

### Implementation Scope

- `cost_tracker.py` — Cost accumulator with pattern matching for provider/model estimation, sliding window for per-minute tracking, session total
- `policy_loader.py` — Parse cost_limits section, validate patterns, optionally load external cost file
- `gate.py` — Check cost limits alongside rate limits (before classification), pass `cost_context` to OPA
- `audit.py` — Add `cost_est` and `session_cost_total` to audit records
- `yaml_to_rego.py` — Compile cost threshold rules for OPA evaluation
- Agent feedback — Include cost status: "Session cost: $4.27 of $25.00 budget.  This call est: $0.075 (anthropic/claude-opus)."

### What This Unlocks

- Budget enforcement aware of provider and model pricing differences
- FinOps visibility into agent operations — which models are consuming the budget
- Per-tool, per-provider cost awareness for policy tuning
- Role-based budgets via OPA (admin gets $100, restricted gets $10)
- Composed decisions (cost × tier × identity) in OPA
- Foundation for chargeback in multi-tenant deployments
- Separation of pricing data from security policy (external cost file)

---

## Phase 9: Telemetry Export (v0.4.0)

**Target:** April 2026
**AARM:** R8 (Telemetry Export) — currently ⚠️ Foundation Laid
**Strategic:** Table stakes for enterprise deployment where centralized logging is mandatory.

### The Problem

Agent Gate writes JSONL to local files.  Enterprise environments require structured event export to centralized SIEM/SOAR platforms (Splunk, Elastic, Sentinel, etc.).  The data shape is ready — the transport is missing.

### Deliverables

**Configuration:**

```yaml
logging:
  # Existing JSONL logging unchanged

  export:
    # Syslog (most universal)
    syslog:
      enabled: true
      host: "siem.corp.internal"
      port: 514
      protocol: "tcp"           # "tcp" | "udp" | "tls"
      facility: "auth"
      format: "cef"             # "cef" | "json" | "ocsf"

    # Webhook (flexible)
    webhook:
      enabled: false
      url: "https://hooks.corp.internal/agent-gate"
      headers:
        Authorization: "Bearer ${AGENT_GATE_WEBHOOK_TOKEN}"
      batch_size: 10
      flush_interval_seconds: 5

    # OpenTelemetry (emerging standard)
    otlp:
      enabled: false
      endpoint: "https://otel-collector.corp.internal:4317"
```

**Implementation scope:**

- `telemetry.py` — Exporter interface with syslog, webhook, and OTLP backends
- `audit.py` — Hook exporters into the logging pipeline (export alongside local write)
- CEF and OCSF schema mappings for SIEM compatibility
- Batching and retry logic for webhook delivery

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R8 (Telemetry Export) | ⚠️ Foundation Laid | ✅ Satisfied — structured export to SIEM/SOAR |

---

## Phase 10: Signed Receipts (v0.5.0)

**Target:** May 2026
**AARM:** R5 (Tamper-Evident Receipts) — currently ⚠️ Partial
**Depends on:** Phase 6 (Identity) for identity-bound signatures

### The Problem

Hash chaining proves integrity (tampering is detectable).  Policy hash proves configuration accountability.  But neither proves authorship.  Full non-repudiation requires cryptographic signing: given a receipt, an auditor can verify who made the decision, under what policy, with what context, and confirm it hasn't been modified.

### Deliverables

**Signing infrastructure:**

- Process-local key generation at gate startup (minimum viable)
- Optional KMS/HSM integration for production environments
- Receipt schema binding `(action, identity, context, policy_hash, decision, timestamp)` as a signed artifact
- Verification CLI: `agent-gate verify-receipt <receipt_file>`

**Implementation scope:**

- `receipts.py` — Receipt generation and signing (Ed25519 or RSA)
- `audit.py` — Emit signed receipt alongside JSONL record
- `cli.py` — `verify-receipt` command for offline verification
- Key management: generate, rotate, export public key

### AARM Advancement

| Requirement | Before | After |
|---|---|---|
| R5 (Tamper-Evident Receipts) | ⚠️ Partial | ✅ Satisfied — signed receipts with identity binding |

### NIST Advancement

| Control | Before | After |
|---|---|---|
| AU-10 (Non-repudiation) | ⚠️ Partial | ✅ Implemented — identity-bound signed receipts |

---

## Deferred (Post v0.5.0)

### DEFER Decision (AARM R4)

Requires an async hold queue and a mechanism to revisit deferred actions when additional context arrives.  The current proxy operates synchronously — DEFER requires an architectural shift to event-driven processing.  Worth building once an approval service exists for STEP_UP completion, since both need the same async infrastructure.

### Semantic Distance Tracking (AARM R7)

Requires embedding infrastructure to compute similarity between the original user request and current agent actions.  Architecturally heavy, requires a model in the evaluation loop (contradicts the "pre-computed, no LLM at runtime" principle).  Interesting for drift detection but not where the adoption leverage is.  Consider as an optional plugin rather than core functionality.

### Session Context Accumulator (AARM R2, full)

The rate tracker provides operational context.  Full AARM R2 wants semantic context: ordered action history, data sensitivity tracking, original intent capture.  This is a prerequisite for DEFER and semantic distance, so it naturally follows them.  The foundation is laid with `rate_context` — extending it to a full session context store is incremental.

### Progressive Autonomy Profiles

Multiple rate limit profiles (conservative/standard/permissive) that agents graduate between based on demonstrated reliability.  The rate limiting infrastructure supports this — it's a policy design pattern on top of existing mechanisms.

---

## Version Plan

| Version | Codename | Key Capabilities | Target |
|---|---|---|---|
| **v0.2.0** | — | Rate limiting, circuit breaker, policy hash | ✅ Released 2026-02-23 |
| **v0.3.0** | Identity | Identity binding, RBAC, role-based policy overrides | ✅ Released 2026-02-23 |
| **v0.4.0** | Enterprise | MODIFY decisions, cost tracking, telemetry export | April 2026 |
| **v0.5.0** | Receipts | Signed receipts, full non-repudiation | May 2026 |

### AARM Conformance Trajectory

| Version | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | Core Status |
|---|---|---|---|---|---|---|---|---|---|---|
| **v0.2.0** | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ⚠️ | ❌ | 1/6 satisfied |
| **v0.3.0** | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ | 1/6 satisfied, 5/6 partial |
| **v0.4.0** | ✅ | ⚠️ | ⚠️ | ⚠️+ | ⚠️ | ⚠️ | ❌ | ✅ | ❌ | 2/6 satisfied |
| **v0.5.0** | ✅ | ⚠️ | ⚠️ | ⚠️+ | ✅ | ⚠️ | ❌ | ✅ | ❌ | 3/6 satisfied |

### NIST SP 800-53 Gap Trajectory

| Version | ❌ Gaps | ✅ Implemented | Notes |
|---|---|---|---|
| **v0.2.0** | 1 (AC-3(7)) | 22 of 29 | Rate limiting closed AU-9(3) and AU-10 gaps |
| **v0.3.0** | 0 | 23 of 31 | Identity closes AC-3(7), adds IA-2 and IA-4 |
| **v0.5.0** | 0 | 26 of 33 | Signed receipts fully satisfies AU-10 |

---

## External Milestones

| Date | Milestone | Agent Gate Dependency |
|---|---|---|
| **10 Mar 2026** | LinkedIn Post 5 (first comment with repo link, 0700 CT) | v0.2.0 rate limiting content |
| **17 Mar 2026** | LinkedIn Post 7 (first comment with repo link, 0700 CT) | Identity work in progress |
| **April 2026** | NCCoE concept paper on AI Agent Identity and Authorization | v0.3.0 identity binding as reference implementation |
| **Ongoing** | AARM community engagement | AARM_Alignment.md progression as visible evidence |

---

## Execution Principles

1. **Each phase ships with tests, updated compliance docs, and updated AARM alignment.**  Documentation is not a follow-up task — it ships with the code.

2. **Backward compatibility is non-negotiable.**  Every new feature is optional.  Existing policies work without modification.

3. **Each version is a credible milestone.**  v0.3.0 can stand alone as "execution authority with identity."  v0.4.0 can stand alone as "enterprise-ready agent governance."  No version depends on the next to be useful.

4. **Implementation evidence over theoretical proposals.**  Every NIST submission and LinkedIn post references working code, passing tests, and honest gap assessments.

5. **The NCCoE paper deadline drives Phase 6 priority.**  Identity binding must be implemented, tested, and documented before the April submission.
