# AARM Alignment Assessment — Agent Gate

**Document version:** 0.1.0
**Agent Gate version:** 0.1.0
**AARM Specification version:** v0.1
**Date:** 2026-02-19
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

AARM defines four action categories. Agent Gate defines five action tiers. The mapping is partial:

| AARM Category | Description | Agent Gate Tier | Status |
|---|---|---|---|
| **Forbidden** | Always blocked regardless of context | `BLOCKED` | ✅ Direct mapping |
| **Context-Dependent Deny** | Allowed by policy but blocked when context reveals inconsistency with intent | — | ❌ Not implemented — no context-awareness layer |
| **Context-Dependent Allow** | Denied by default but permitted when context confirms legitimate intent | — | ❌ Not implemented |
| **Context-Dependent Defer** | Suspended when context is insufficient for a confident decision | — | ❌ Not implemented |

Agent Gate's additional tiers that do not map directly to AARM categories:

| Agent Gate Tier | Behavior | Nearest AARM Analog |
|---|---|---|
| `DESTRUCTIVE` | Allowed after mandatory vault backup succeeds | Partial — static policy with pre-condition (backup), not context-dependent |
| `NETWORK` | Default escalate for human approval | Partial — resembles STEP_UP but without context evaluation |
| `READ_ONLY` | Auto-allow within envelope | Implicit allow — not a distinct AARM category |
| `UNCLASSIFIED` | Default deny with feedback | Closest to Forbidden, but reason is lack of classification rather than policy prohibition |

**Key gap:** AARM's classification framework is fundamentally context-dependent — an action's category can change based on accumulated session state. Agent Gate classifies actions based on static pattern matching against the tool call structure alone. Agent Gate evaluates the tuple `(action)` rather than AARM's required `(action, context)`.

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

#### R2: Context Accumulation ⚠️ Partial

> *Requirement: Track prior actions, data classifications, and original request in an append-only, tamper-evident log.*

Agent Gate logs all tool calls to a JSONL audit log with timestamps, tool names, arguments, verdicts, tiers, and reasons. However, this falls short of AARM's context accumulation requirements in several ways:

| AARM Requirement | Agent Gate Status |
|---|---|
| Track prior actions | ✅ Audit log records all tool calls with verdicts |
| Append-only log | ✅ JSONL file opened in append mode |
| Hash-chained entries | ❌ Not implemented — entries are not cryptographically linked |
| Session-level context tracking | ⚠️ `session_id` field exists but context is not accumulated across actions |
| Original user request | ❌ Not captured — the proxy sees tool calls, not the user's original intent |
| Data classifications | ❌ No data sensitivity tracking |
| Context available to policy engine | ❌ Audit log is write-only — not queried during evaluation |

**Implementation evidence:**
- `audit.py`: `AuditLogger.log()` writes structured records to JSONL, including `session_id` and `server_name`
- `audit.py`: `AuditRecord` captures `timestamp`, `tool_name`, `arguments`, `verdict`, `tier`, `reason`, `vault_path`, `duration_ms`
- No mechanism exists to feed accumulated context back into policy evaluation

**Gap:** The audit log is a post-hoc record, not a live context accumulator. AARM requires that accumulated context influences authorization decisions — Agent Gate's audit log is not read during evaluation.

---

#### R3: Policy Evaluation with Intent Alignment ⚠️ Partial

> *Requirement: Evaluate actions against static policy AND contextual intent alignment, supporting forbidden, context-dependent deny, context-dependent allow, and context-dependent defer classifications.*

Agent Gate implements static policy evaluation with two classifier backends (Python and OPA). It does not implement intent alignment or context-dependent classification.

| AARM Requirement | Agent Gate Status |
|---|---|
| Static policy evaluation | ✅ YAML-defined rules, pattern matching, envelope enforcement |
| Forbidden classification | ✅ `BLOCKED` tier with hard deny |
| Context-dependent deny | ❌ Not implemented |
| Context-dependent allow | ❌ Not implemented |
| Context-dependent defer | ❌ Not implemented |
| Intent alignment evaluation | ❌ Not implemented |
| Pluggable policy language | ✅ Python and OPA/Rego backends |

**Implementation evidence:**
- `classifier_base.py`: `ClassifierBase.classify()` evaluates tool calls based on command name, argument patterns, and path envelope
- `classifier.py`: `PythonClassifier._evaluate()` performs static pattern matching
- `opa_classifier.py`: `OPAClassifier` delegates to Open Policy Agent for policy evaluation
- `gate.py`: Tier-based routing — no context input to any evaluation path

**Note:** AARM explicitly states that implementations may use OPA, Cedar, or custom DSLs as their policy engine, provided the engine can evaluate the tuple `(action, context)`. Agent Gate's OPA integration satisfies the policy engine requirement structurally — the gap is in providing context to that engine.

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

#### R5: Tamper-Evident Receipts ⚠️ Partial

> *Requirement: Cryptographically signed records binding action, context, decision, and outcome.*

Agent Gate has structured logging and SHA-256 integrity verification for vault snapshots, but does not produce AARM-conformant receipts.

| AARM Requirement | Agent Gate Status |
|---|---|
| Structured action records | ✅ JSONL audit records with tool name, arguments, verdict, tier, reason |
| Decision recorded | ✅ Verdict and reason logged |
| Context binding | ❌ No session context included in records |
| Outcome binding | ❌ Action outcome (success/failure of tool execution) not captured |
| Cryptographic signing | ❌ Records are not signed |
| Hash-chaining | ❌ Records are not linked to prior entries |
| Offline verification | ❌ No mechanism to verify receipt integrity independently |
| Vault snapshot integrity | ✅ SHA-256 hashes computed for all vault backups |

**Implementation evidence:**
- `audit.py`: `AuditRecord.to_json()` produces structured records but without cryptographic properties
- `vault.py`: `VaultManager._file_sha256()` computes SHA-256 for backup integrity verification
- `vault.py`: `VaultSnapshot` dataclass includes `sha256` field for each backed-up file
- No receipt schema binding `(action, context, decision, outcome)` as a single signed artifact

**Gap:** AARM receipts must enable forensic reconstruction — given a receipt, an auditor should be able to verify what action was proposed, what context existed at decision time, what decision was made and why, and what the outcome was. Agent Gate's audit records capture the decision but not the full binding.

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

#### R8: Telemetry Export ❌ Not Implemented

> *Requirement: Structured event export to SIEM/SOAR platforms.*

Agent Gate writes JSONL audit logs to local files. There is no export mechanism to external telemetry systems.

**Starting point:** The JSONL format is a reasonable foundation. The records include structured fields (timestamp, tool name, verdict, tier) that map to common SIEM event schemas. The gap is in transport (no syslog, no webhook, no OpenTelemetry export) and in schema compliance (no CEF, no OCSF mapping).

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
| **R2** | MUST | Context accumulation | ⚠️ Partial | Audit log exists; no hash-chaining, no context feedback to policy engine |
| **R3** | MUST | Policy evaluation with intent alignment | ⚠️ Partial | Static policy evaluation implemented; no context-dependent classification |
| **R4** | MUST | Five authorization decisions | ⚠️ Partial | ALLOW and DENY implemented; ESCALATE ≈ STEP_UP without completion; no MODIFY or DEFER |
| **R5** | MUST | Tamper-evident receipts | ⚠️ Partial | Structured JSONL logging; SHA-256 on vault snapshots; no signed receipts |
| **R6** | MUST | Identity binding | ❌ Gap | Session UUID only; no human/agent/service/role identity |
| **R7** | SHOULD | Semantic distance tracking | ❌ Gap | No embedding or drift detection |
| **R8** | SHOULD | Telemetry export | ❌ Gap | JSONL foundation exists; no SIEM/SOAR transport |
| **R9** | SHOULD | Least privilege / JIT credentials | ❌ Gap | Aligns with planned JIT authority grants feature |

**AARM Core (R1–R6):** 1 of 6 fully satisfied. 4 of 6 partially satisfied. 1 gap.
**AARM Extended (R7–R9):** 0 of 3 satisfied.

---

## Path to AARM Core Conformance

The following outlines what Agent Gate would need to reach AARM Core (R1–R6) conformance. Items are ordered by implementation dependency, not priority.

### 1. Context Accumulator (R2)

Build a session-scoped context store that tracks:
- Original user request (if available from the protocol)
- Ordered list of prior tool calls and their verdicts
- Data classifications of accessed resources
- Hash-chain linking each entry to its predecessor

Make this context available as input to the policy engine at evaluation time.

### 2. Context-Dependent Classification (R3)

Extend the classifier interface to accept accumulated context alongside the tool call. This enables policies that reference prior actions — for example, denying file exfiltration after sensitive data was read in the same session, even though the exfiltration action would be permitted in isolation.

The OPA backend is well-positioned for this: Rego policies can evaluate the `(action, context)` tuple natively once context is provided as input.

### 3. MODIFY and DEFER Decisions (R4)

**MODIFY** requires a mechanism to rewrite tool call parameters before forwarding to the server. The MCP proxy already serializes/deserializes JSON-RPC messages — parameter rewriting is a tractable addition.

**DEFER** requires a hold queue and a mechanism to revisit deferred actions when additional context arrives. This is a more significant architectural addition, as the current proxy operates synchronously.

**STEP_UP completion** requires an approval service — a mechanism (webhook, Slack integration, CLI prompt) to collect human approval and resume a held action.

### 4. Signed Receipts (R5)

Extend audit records to bind `(action, context_snapshot, decision, outcome)` as a single artifact. Sign receipts with a process-local key (minimum) or an HSM/KMS-backed key (production). Implement hash-chaining so each receipt references its predecessor.

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
| Feedback on denial | Authorization decisions include reasons and remediation paths | `GateDecision` includes `denial_feedback` and `escalation_hint` |
| Policy-as-code | Declarative policy definitions | YAML policies with OPA/Rego backend option |
| Agent-unreachable recovery | — | Vault-backed rollback ensures destructive actions are recoverable |

Agent Gate's vault-backed rollback pattern is not addressed by AARM but represents a complementary capability: ensuring that even when a destructive action is authorized and executed, recovery remains possible through agent-unreachable backup storage.

---

## References

- Errico, H. "Autonomous Action Runtime Management (AARM): A System Specification for Securing AI-Driven Actions at Runtime." AARM Specification v0.1, 2025. [https://aarm.dev](https://aarm.dev)
- Errico, H. arXiv:2602.09433. [https://arxiv.org/abs/2602.09433](https://arxiv.org/abs/2602.09433)
- Agent Gate repository: [https://github.com/SeanFDZ/agent-gate](https://github.com/SeanFDZ/agent-gate)
