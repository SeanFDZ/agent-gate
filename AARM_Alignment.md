# AARM Alignment Assessment — Agent Gate

**Document version:** 0.2.0
**Agent Gate version:** 0.2.0 (Phase 5: Rate Limiting & Circuit Breaker)
**AARM Specification version:** v0.1
**Date:** 2026-02-23
**Status:** Gap analysis — this is NOT a conformance claim

---

## Overview

This document maps Agent Gate's current implementation against the [Autonomous Action Runtime Management (AARM)](https://aarm.dev) specification v0.1 by Herman Errico ([arXiv:2602.09433](https://arxiv.org/abs/2602.09433)).

AARM is an open system specification for securing AI-driven actions at runtime. It defines what a runtime security system must do — intercept actions before execution, accumulate session context, evaluate against policy and intent alignment, enforce authorization decisions, and record tamper-evident receipts. AARM is model-agnostic, framework-agnostic, and vendor-neutral.

Agent Gate is an execution authority layer that intercepts AI agent tool calls before execution and enforces policy-based authorization. This assessment provides an honest mapping of where Agent Gate satisfies AARM requirements, where partial alignment exists, and where gaps remain. The goal is transparency about current capabilities and a clear path toward AARM Core conformance.

---

## Architecture Alignment

AARM defines four implementation architectures. Agent Gate's MCP proxy maps to the **Protocol Gateway** architecture:

| AARM Property | Protocol Gateway (AARM) | Agent Gate (Current) |
|---|---|---|
| **Control level** | Network | Network (stdio MCP proxy) |
| **Bypass resistance** | High | High — all tool calls transit the proxy |
| **Context richness** | Limited | Limited — sees tool calls and verdicts, not model reasoning |
| **Defer support** | Partial | Not implemented |
| **AARM-conformant standalone** | Yes | Not yet — gaps in R2–R6 |

Agent Gate's architecture places enforcement at the protocol boundary between client and server. The proxy is transparent to both sides: the client believes it is communicating with the MCP server directly, and the server believes it is communicating with the client. This is architecturally consistent with AARM's Protocol Gateway model, where enforcement occurs at a chokepoint with high bypass resistance.

---

## Action Classification Mapping

AARM defines four action categories. Agent Gate defines six action tiers. The mapping is partial, with recent progress on context-dependent decisions:

| AARM Category | Description | Agent Gate Tier | Status |
|---|---|---|---|
| **Forbidden** | Always blocked regardless of context | `BLOCKED` | ✅ Direct mapping |
| **Context-Dependent Deny** | Allowed by policy but blocked when context reveals inconsistency with intent | `RATE_LIMITED` | ⚠️ Partial — circuit breaker denies otherwise-allowed actions based on accumulated operational context (failure rates, tempo); not yet intent-aware |
| **Context-Dependent Allow** | Denied by default but permitted when context confirms legitimate intent | — | ❌ Not implemented |
| **Context-Dependent Defer** | Suspended when context is insufficient for a confident decision | — | ❌ Not implemented |

Agent Gate's additional tiers that do not map directly to AARM categories:

| Agent Gate Tier | Behavior | Nearest AARM Analog |
|---|---|---|
| `DESTRUCTIVE` | Allowed after mandatory vault backup succeeds | Partial — static policy with pre-condition (backup), not context-dependent |
| `NETWORK` | Default escalate for human approval | Partial — resembles STEP_UP but without context evaluation |
| `READ_ONLY` | Auto-allow within envelope | Implicit allow — not a distinct AARM category |
| `UNCLASSIFIED` | Default deny with feedback | Closest to Forbidden, but reason is lack of classification rather than policy prohibition |
| `RATE_LIMITED` | Denied due to operational tempo violation | Context-Dependent Deny — same action is allowed when breaker is CLOSED but denied when OPEN |

**Key gap (narrowing):** AARM's classification framework is fundamentally context-dependent — an action's category can change based on accumulated session state.  Agent Gate now has a limited form of this: the circuit breaker and rate limiter make authorization decisions that depend on accumulated operational context (call counts, failure rates, breaker state).  The same `rm` command is allowed when the breaker is CLOSED but denied when it's OPEN.  However, this context is operational tempo, not semantic intent.  Agent Gate evaluates `(action, operational_context)` rather than AARM's full `(action, intent_context)`.

---

## Conformance Requirements Mapping

### AARM Core (R1–R6) — MUST

#### R1: Pre-Execution Interception ✅ Satisfied

> *Requirement: Block or defer actions before execution.*

Agent Gate's core architecture satisfies R1. The MCP proxy intercepts `tools/call` JSON-RPC requests before forwarding them to the real MCP server. Denied or escalated actions are never forwarded — the client receives a structured error response instead.

**Implementation evidence:**
- `mcp_proxy.py`: `MCPProxy._handle_tool_call()` evaluates every tool call through `Gate.evaluate()` before forwarding
- `gate.py`: `Gate.evaluate()` returns a `GateDecision` with `Verdict.ALLOW`, `Verdict.DENY`, or `Verdict.ESCALATE`
- On `DENY` or `ESCALATE`, the proxy returns an error response to the client and does not forward the request to the server
- On `ALLOW`, the request is forwarded to the real server for execution

**Bypass resistance:** High. All MCP communication transits the proxy's stdio pipes. There is no alternative path for tool calls to reach the server without passing through the gate.

---

#### R2: Context Accumulation ⚠️ Partial (Improved)

> *Requirement: Track prior actions, data classifications, and original request in an append-only, tamper-evident log.*

Agent Gate logs all tool calls to a JSONL audit log with timestamps, tool names, arguments, verdicts, tiers, reasons, and policy hashes.  The rate tracker now maintains session-level operational context that accumulates across tool calls and influences authorization decisions.

| AARM Requirement | Agent Gate Status |
|---|---|
| Track prior actions | ✅ Audit log records all tool calls with verdicts |
| Append-only log | ✅ JSONL file opened in append mode |
| Hash-chained entries | ✅ SHA-256 hash chaining — each record includes `prev_hash` and `record_hash` |
| Session-level context tracking | ⚠️ Rate tracker maintains sliding window counters, circuit breaker state, and backoff history per session; `rate_context` snapshot included in audit records for rate-limited decisions |
| Context available to policy engine | ⚠️ Rate context is computed by the gate and passed to OPA as input; circuit breaker state influences authorization decisions |
| Original user request | ❌ Not captured — the proxy sees tool calls, not the user's original intent |
| Data classifications | ❌ No data sensitivity tracking |

**Implementation evidence:**
- `audit.py`: `AuditRecord` includes `policy_hash` (SHA-256 of governing policy) and `rate_context` (operational state snapshot) fields
- `audit.py`: SHA-256 hash chaining via `prev_hash` and `record_hash` fields with `verify_chain()` for integrity verification
- `rate_tracker.py`: `RateTracker` maintains per-tool sliding window counters, per-tier aggregate counters, global counter, and three-state circuit breaker — all accumulated across the session
- `rate_tracker.py`: `get_rate_context()` returns a snapshot of accumulated state for audit records and OPA input
- `gate.py`: Circuit breaker state and rate limits directly influence authorization decisions — context feeds back into the policy evaluation pipeline

**Remaining gap:** The accumulated context is operational (call counts, failure rates, timing) rather than semantic (original intent, data sensitivity).  AARM's full R2 envisions context that captures why the user initiated the session and tracks semantic drift from that intent.  Agent Gate's rate context answers "how fast is this agent operating?" but not "is this agent still doing what it was asked to do?"

---

#### R3: Policy Evaluation with Intent Alignment ⚠️ Partial (Improved)

> *Requirement: Evaluate actions against static policy AND contextual intent alignment, supporting forbidden, context-dependent deny, context-dependent allow, and context-dependent defer classifications.*

Agent Gate implements static policy evaluation with two classifier backends (Python and OPA), and now implements a limited form of context-dependent deny through rate limiting and the circuit breaker.  It does not implement intent alignment or context-dependent allow/defer.

| AARM Requirement | Agent Gate Status |
|---|---|
| Static policy evaluation | ✅ YAML-defined rules, pattern matching, envelope enforcement |
| Forbidden classification | ✅ `BLOCKED` tier with hard deny |
| Context-dependent deny | ⚠️ Circuit breaker denies otherwise-allowed actions when failure rate exceeds threshold; rate limits deny when operational tempo is exceeded.  Context is operational, not semantic. |
| Context-dependent allow | ❌ Not implemented |
| Context-dependent defer | ❌ Not implemented |
| Intent alignment evaluation | ❌ Not implemented |
| Pluggable policy language | ✅ Python and OPA/Rego backends |

**Implementation evidence:**
- `classifier_base.py`: `ActionTier` enum now includes `RATE_LIMITED` alongside `BLOCKED`, `DESTRUCTIVE`, `NETWORK`, `READ_ONLY`, `UNCLASSIFIED`
- `gate.py`: `Gate.evaluate()` checks circuit breaker state and rate limits before classification — the same action produces different decisions based on accumulated operational context
- `rate_tracker.py`: `CircuitBreaker` implements CLOSED → OPEN → HALF_OPEN → CLOSED state machine; `SlidingWindowCounter` tracks per-tool, per-tier, and global call rates
- `yaml_to_rego.py`: Rate limit thresholds compile to Rego rules, enabling OPA to evaluate `(action, rate_context)` tuples
- `opa_classifier.py`: OPA receives `rate_context` in input, evaluating rate thresholds alongside static policy

**Remaining gap:** The context-dependent decisions are limited to operational tempo (how fast, how often, how many failures).  AARM's full R3 envisions context that includes the session's purpose, accumulated data sensitivity, and semantic drift from original intent.  Agent Gate's circuit breaker is a mechanical safety control, not an intent alignment check.

**Note:** AARM explicitly states that implementations may use OPA, Cedar, or custom DSLs as their policy engine, provided the engine can evaluate the tuple `(action, context)`.  Agent Gate's OPA integration now partially satisfies this: the `yaml_to_rego.py` compiler generates rate limit threshold rules, and the gate passes `rate_context` as part of the OPA input, enabling Rego policies to evaluate `(action, rate_context)`.  The remaining gap is providing full session context (action history, data sensitivity, original intent) to the policy engine.

---

#### R4: Five Authorization Decisions ⚠️ Partial

> *Requirement: Implement ALLOW, DENY, MODIFY, STEP_UP, and DEFER.*

Agent Gate implements three of AARM's five authorization decisions:

| AARM Decision | Description | Agent Gate | Status |
|---|---|---|---|
| **ALLOW** | Action proceeds | `Verdict.ALLOW` | ✅ Implemented |
| **DENY** | Action blocked with reason | `Verdict.DENY` | ✅ Implemented with denial feedback and escalation hints |
| **MODIFY** | Action parameters altered to conform to policy | — | ❌ Not implemented |
| **STEP_UP** | Action paused pending human approval | `Verdict.ESCALATE` | ⚠️ Functionally similar — returns error with escalation hint, but no approval workflow to resume |
| **DEFER** | Action suspended pending additional context | — | ❌ Not implemented |

**Implementation evidence:**
- `gate.py`: `Verdict` enum defines `ALLOW`, `DENY`, `ESCALATE`
- `gate.py`: `GateDecision.to_agent_message()` returns structured denial feedback including reason and escalation path
- `gate.py`: `_handle_network()` uses `ESCALATE` for network actions, functionally similar to STEP_UP
- No mechanism exists to hold an action, collect approval, and resume execution

**Gap — MODIFY:** Agent Gate cannot rewrite tool call parameters. For example, AARM envisions modifying a query to add `LIMIT 100` rather than denying it outright. Agent Gate would deny or allow the original action as-is.

**Gap — DEFER:** Agent Gate has no mechanism to suspend an action and revisit it when additional context becomes available. Actions are decided synchronously and immediately.

**Gap — STEP_UP completion:** While `ESCALATE` signals that human approval is needed, there is no approval service to collect that approval and allow the action to proceed. The current implementation effectively converts STEP_UP to a DENY with an explanation.

---

#### R5: Tamper-Evident Receipts ⚠️ Partial (Improved)

> *Requirement: Cryptographically signed records binding action, context, decision, and outcome.*

Agent Gate has structured logging with SHA-256 hash chaining for tamper evidence, policy hash binding for configuration traceability, and rate context snapshots on rate-limited decisions.  It does not yet produce fully AARM-conformant signed receipts.

| AARM Requirement | Agent Gate Status |
|---|---|
| Structured action records | ✅ JSONL audit records with tool name, arguments, verdict, tier, reason |
| Decision recorded | ✅ Verdict and reason logged |
| Hash-chaining | ✅ SHA-256 `prev_hash` and `record_hash` fields; `verify_chain()` detects tampering |
| Policy binding | ✅ `policy_hash` (truncated SHA-256) on every record — proves which policy version governed each decision |
| Context binding | ⚠️ `rate_context` snapshot included on rate-limited decisions; not included on all decisions |
| Outcome binding | ❌ Action outcome (success/failure of tool execution) not captured |
| Cryptographic signing | ❌ Records are hash-chained but not signed with a key |
| Offline verification | ⚠️ `verify_chain()` verifies hash chain integrity; no signature verification |
| Vault snapshot integrity | ✅ SHA-256 hashes computed for all vault backups |

**Implementation evidence:**
- `audit.py`: `AuditRecord` includes `policy_hash`, `rate_context`, `prev_hash`, and `record_hash` fields
- `audit.py`: `verify_chain()` walks the log and confirms hash chain integrity in a single pass
- `policy_loader.py`: `Policy.policy_hash` computes deterministic SHA-256 from sorted JSON of the raw policy
- `gate.py`: Every logged decision includes `policy_hash`; rate-limited decisions additionally include `rate_context`
- `vault.py`: `VaultSnapshot` dataclass includes `sha256` field for each backed-up file

**Remaining gap:** AARM receipts must bind `(action, context, decision, outcome)` as a single signed artifact.  Agent Gate binds action + decision + policy_hash + partial context, but does not capture the outcome of tool execution (did the action succeed after the gate allowed it?), does not include full session context on every record, and does not sign records with a cryptographic key.  The hash chain provides tamper evidence (modification is detectable) but not non-repudiation (cannot prove who created the record).

---

#### R6: Identity Binding ❌ Gap

> *Requirement: Bind actions to identity at five levels — human, service, agent, session, and role/privilege scope.*

Agent Gate does not implement identity binding. The proxy generates a session UUID and tracks a server name, but does not authenticate, authorize, or bind any identity to actions.

| AARM Identity Level | Agent Gate Status |
|---|---|
| Human identity | ❌ No user/operator identity |
| Service identity | ⚠️ Server name captured in audit log |
| Agent identity | ❌ No agent identity tracking |
| Session identity | ⚠️ UUID-based `session_id` generated per proxy lifecycle |
| Role/privilege scope | ❌ No RBAC, no role-based policy differentiation |

**Implementation evidence:**
- `mcp_proxy.py`: `self.session_id = str(uuid.uuid4())[:8]` — session-scoped but not identity-bound
- `audit.py`: `AuditRecord.session_id` and `AuditRecord.server_name` fields exist
- No authentication mechanism at any layer

**Gap:** This is Agent Gate's largest structural gap relative to AARM Core. Identity binding requires integration with external identity providers (OAuth, OIDC, mTLS certificates, API keys) and a mechanism to propagate identity through the evaluation pipeline so that policies can differentiate authorization based on who is requesting the action, not just what the action is.

---

### AARM Extended (R7–R9) — SHOULD

#### R7: Semantic Distance Tracking ❌ Not Implemented

> *Requirement: Detect intent drift via embedding similarity between original request and current actions.*

Agent Gate does not implement semantic analysis. All classification is structural (command names, argument patterns, path matching). There is no embedding computation, no similarity scoring, and no drift detection.

This is architecturally consistent with Agent Gate's current design philosophy of inspecting the action rather than the reasoning. AARM's R7 would require Agent Gate to capture the original user intent and compute semantic distance as actions accumulate — a significant architectural addition.

---

#### R8: Telemetry Export ⚠️ Foundation Laid

> *Requirement: Structured event export to SIEM/SOAR platforms.*

Agent Gate writes JSONL audit logs to local files with structured fields designed for downstream consumption.  There is no export mechanism to external telemetry systems, but the data shape is designed for it.

**Starting point:** The JSONL records include structured fields (timestamp, tool name, verdict, tier, policy_hash, rate_context, duration_ms) that map to common SIEM event schemas.  The `rate_context` snapshots include counter values, breaker state, and limit configurations — the kind of operational telemetry that SIEM/SOAR platforms consume for anomaly detection and alerting.  The gap is in transport (no syslog, no webhook, no OpenTelemetry export) and in schema compliance (no CEF, no OCSF mapping).

---

#### R9: Least Privilege with Scoped JIT Credentials ❌ Not Implemented

> *Requirement: Just-in-time credential issuance with scope and temporal limits.*

Agent Gate does not manage credentials. MCP server credentials pass through the proxy environment to the server subprocess without Agent Gate's involvement.

**Planned alignment:** Agent Gate's roadmap includes JIT authority grants — temporary policy overlays with approver, scope, and automatic expiration. This concept aligns with R9 directionally, though AARM's requirement extends to credential management (OAuth token scoping, temporary API keys) rather than policy overlay alone.

---

## Summary Matrix

| Requirement | Level | Description | Status | Notes |
|---|---|---|---|---|
| **R1** | MUST | Pre-execution interception | ✅ Satisfied | Core architecture — MCP proxy intercepts all tool calls |
| **R2** | MUST | Context accumulation | ⚠️ Partial (improved) | Hash-chained audit log; rate tracker accumulates session-level operational context; context feeds back to policy engine via circuit breaker and OPA input; no intent tracking |
| **R3** | MUST | Policy evaluation with intent alignment | ⚠️ Partial (improved) | Static policy + context-dependent deny via circuit breaker and rate limits; no intent alignment |
| **R4** | MUST | Five authorization decisions | ⚠️ Partial | ALLOW and DENY implemented; ESCALATE ≈ STEP_UP without completion; no MODIFY or DEFER |
| **R5** | MUST | Tamper-evident receipts | ⚠️ Partial (improved) | Hash-chained JSONL with policy_hash binding and rate_context snapshots; no cryptographic signing |
| **R6** | MUST | Identity binding | ❌ Gap | Session UUID only; no human/agent/service/role identity |
| **R7** | SHOULD | Semantic distance tracking | ❌ Gap | No embedding or drift detection |
| **R8** | SHOULD | Telemetry export | ⚠️ Foundation laid | Structured JSONL with OpenTelemetry-ready fields; no SIEM/SOAR transport |
| **R9** | SHOULD | Least privilege / JIT credentials | ❌ Gap | Aligns with planned JIT authority grants feature |

**AARM Core (R1–R6):** 1 of 6 fully satisfied.  4 of 6 partially satisfied (3 improved since v0.1.0).  1 gap.
**AARM Extended (R7–R9):** 0 of 3 fully satisfied.  1 foundation laid.

---

## Path to AARM Core Conformance

The following outlines what Agent Gate would need to reach AARM Core (R1–R6) conformance. Items are ordered by implementation dependency, not priority.

### 1. Context Accumulator (R2) — In Progress

Agent Gate now maintains session-level operational context via the rate tracker (sliding window counters, circuit breaker state, backoff history) and records this context in audit logs.  Remaining work:

- Capture the original user request (if available from the MCP protocol or client metadata)
- Track data classifications of accessed resources
- Extend `rate_context` to include a summary of prior actions (not just counts, but the sequence of tool calls and verdicts)
- Make the full accumulated context available to the OPA policy engine (currently only rate_context is passed)

### 2. Context-Dependent Classification (R3) — In Progress

Agent Gate now implements context-dependent deny through the circuit breaker (operational context influences authorization).  Remaining work:

- Extend context-dependent decisions beyond operational tempo to include session history — for example, denying file exfiltration after sensitive data was read in the same session, even though the exfiltration action would be permitted in isolation
- The OPA backend is well-positioned for this: Rego policies can evaluate the `(action, context)` tuple natively once full session context is provided as input alongside rate_context
- Implement context-dependent allow — actions denied by default that are permitted when context confirms legitimate intent

### 3. MODIFY and DEFER Decisions (R4)

**MODIFY** requires a mechanism to rewrite tool call parameters before forwarding to the server. The MCP proxy already serializes/deserializes JSON-RPC messages — parameter rewriting is a tractable addition.

**DEFER** requires a hold queue and a mechanism to revisit deferred actions when additional context arrives. This is a more significant architectural addition, as the current proxy operates synchronously.

**STEP_UP completion** requires an approval service — a mechanism (webhook, Slack integration, CLI prompt) to collect human approval and resume a held action.

### 4. Signed Receipts (R5) — In Progress

Agent Gate now has hash-chained audit records with policy hash binding and partial context (rate_context on rate-limited decisions).  Remaining work:

- Extend records to bind outcome (success/failure of tool execution after the gate allowed it)
- Include full session context snapshot on every record, not just rate-limited decisions
- Sign receipts with a process-local key (minimum) or an HSM/KMS-backed key (production) — hash chaining provides tamper detection but not non-repudiation

### 5. Identity Binding (R6)

This is the most significant gap. Options:
- **MCP protocol extension:** If the MCP `initialize` handshake evolves to include client identity claims, the proxy can capture and propagate them
- **Configuration-based:** Bind identity via proxy configuration (operator identity, service account) at startup
- **External authentication:** Integrate with OAuth/OIDC providers for human identity, API key validation for service identity

Minimum viable approach: accept identity claims via environment variables or configuration, propagate through the evaluation pipeline, and include in receipts.

---

## Design Philosophy Alignment

Beyond the conformance requirements, Agent Gate and AARM share foundational principles:

| Principle | AARM | Agent Gate |
|---|---|---|
| Prevention over detection | Actions must be blocked before execution, not just logged | Core design — the gate makes the wrong action unreachable |
| Structured action inspection | Evaluate the action, not the reasoning | Pre-computed classification against tool call structure |
| The interception point exists | All agents output structured tool calls that client code executes | MCP proxy sits in the native gap between model output and tool execution |
| Feedback on denial | Authorization decisions include reasons and remediation paths | `GateDecision` includes `denial_feedback`, `escalation_hint`, and `rate_status` with remaining budget and reset timing |
| Policy-as-code | Declarative policy definitions | YAML policies with OPA/Rego backend option; rate limits and circuit breaker thresholds defined at design time |
| Context-dependent decisions | Actions evaluated against accumulated session state | Circuit breaker and rate limiter make decisions based on accumulated operational context (tempo, not yet intent) |
| Configuration traceability | — | `policy_hash` on every audit record proves which policy version governed each decision |
| Agent-unreachable recovery | — | Vault-backed rollback ensures destructive actions are recoverable |

Agent Gate's vault-backed rollback pattern is not addressed by AARM but represents a complementary capability: ensuring that even when a destructive action is authorized and executed, recovery remains possible through agent-unreachable backup storage.

---

## Changelog

### v0.2.0 (2026-02-23) — Rate Limiting & Circuit Breaker

Phase 5 implementation (rate limiting, circuit breaker, policy hash traceability) advanced alignment on four AARM requirements:

- **R2 (Context Accumulation):** Rate tracker now maintains session-level operational context (sliding window counters, circuit breaker state, backoff history) that accumulates across tool calls.  `rate_context` snapshots in audit records.  Hash-chaining implemented with `prev_hash`/`record_hash` and `verify_chain()`.  Context feeds back to policy engine via circuit breaker decisions and OPA input.
- **R3 (Policy Evaluation):** Circuit breaker implements context-dependent deny — the same action produces different authorization decisions based on accumulated operational state.  `RATE_LIMITED` tier added to classification model.  OPA receives `rate_context` in input for threshold evaluation.
- **R5 (Tamper-Evident Receipts):** `policy_hash` on every audit record creates cryptographic binding between each decision and its governing policy version.  `rate_context` on rate-limited decisions provides partial context binding.  Hash-chaining provides tamper evidence.
- **R8 (Telemetry Export):** Audit records now include structured operational telemetry fields (`rate_context`, `policy_hash`, `duration_ms`) designed for downstream SIEM/SOAR consumption.  Moved from "not implemented" to "foundation laid."

### v0.1.0 (2026-02-19) — Initial Assessment

Baseline gap analysis against AARM v0.1.  R1 satisfied; R2-R5 partial; R6 gap; R7-R9 not implemented.

---

## References

- Errico, H. "Autonomous Action Runtime Management (AARM): A System Specification for Securing AI-Driven Actions at Runtime." AARM Specification v0.1, 2025. [https://aarm.dev](https://aarm.dev)
- Errico, H. arXiv:2602.09433. [https://arxiv.org/abs/2602.09433](https://arxiv.org/abs/2602.09433)
- Agent Gate repository: [https://github.com/SeanFDZ/agent-gate](https://github.com/SeanFDZ/agent-gate)
