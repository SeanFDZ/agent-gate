# Compliance Framework Mapping — Agent Gate

**Document version:** 0.2.0
**Agent Gate version:** 0.2.0 (Phase 5: Rate Limiting & Circuit Breaker)
**Date:** 2026-02-23
**Status:** Implementation mapping — this is NOT a certification or accreditation claim

---

## Overview

This document maps Agent Gate's implemented capabilities to controls and requirements in established security, AI governance, and federal policy frameworks. The goal is transparency: showing which controls Agent Gate directly supports, which it partially addresses, and where gaps remain.

Agent Gate is an execution authority layer — it intercepts AI agent tool calls before execution and enforces policy-based authorization with vault-backed rollback and operational tempo controls.  It does not replace a complete security program, identity management system, or organizational AI governance framework.  It addresses a specific and critical gap: controlling what AI agents *do* before they do it, and how fast they do it.

For alignment with the Autonomous Action Runtime Management (AARM) specification, see [AARM_Alignment.md](AARM_Alignment.md).

---

## NIST SP 800-53 Rev. 5 — Security and Privacy Controls

SP 800-53 defines the security control catalog used across federal systems. Agent Gate maps to controls in several families. Each mapping references the specific implementation mechanism.

### Access Control (AC)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **AC-3** | Access Enforcement | Gate evaluates every tool call against policy before execution.  The `Gate.evaluate()` method is the enforcement function — no tool call reaches execution without passing through it.  Tiered classification (read-only, destructive, network, blocked, unclassified, rate-limited) implements differentiated access decisions.  Rate limits and circuit breaker provide dynamic enforcement that adapts to operational context. | ✅ Implemented |
| **AC-3(7)** | Role-Based Access Control | Not implemented. Agent Gate enforces policy uniformly — there is no role or identity differentiation in access decisions. | ❌ Gap |
| **AC-3(8)** | Revocation of Access Authorizations | Policy changes take effect on next gate initialization. There is no runtime revocation mechanism for in-flight sessions. | ⚠️ Partial |
| **AC-4** | Information Flow Enforcement | Envelope enforcement restricts which paths the agent can access. Denied paths (e.g., `~/.ssh/**`, `~/.aws/**`, `/etc/**`) define information flow boundaries. Symlink resolution prevents path traversal. | ✅ Implemented |
| **AC-6** | Least Privilege | Default-deny posture for unclassified actions. The agent operates within a declared envelope — anything outside the envelope is denied. Network access requires explicit policy enablement or human escalation. | ✅ Implemented |
| **AC-6(1)** | Authorize Access to Security Functions | The vault directory is explicitly denied in the agent's envelope. The gate that enforces the envelope is the same gate that protects the vault — the agent cannot modify its own safety mechanisms. | ✅ Implemented |
| **AC-6(9)** | Log Use of Privileged Functions | All tool calls are logged to a structured JSONL audit log, including tool name, arguments, verdict, tier, reason, and timing. Destructive actions include vault snapshot paths. | ✅ Implemented |
| **AC-6(10)** | Prohibit Non-Privileged Users from Executing Privileged Functions | Blocked tier actions (`rm -rf /`, `curl | bash`, `mkfs`) are unconditionally denied regardless of context. No policy override allows them — the pattern match is evaluated before any other logic. | ✅ Implemented |

### Audit and Accountability (AU)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **AU-2** | Event Logging | All tool calls through the MCP proxy generate audit records. Allow, deny, escalate, and passthrough events are all logged. Proxy lifecycle events (startup, shutdown, error) are logged separately. | ✅ Implemented |
| **AU-3** | Content of Audit Records | Each record contains: timestamp (ISO 8601), tool name, arguments, verdict, tier, reason, server name, session ID, message ID, vault path (if applicable), gate evaluation duration in milliseconds, `policy_hash` (SHA-256 of governing policy), and `rate_context` (operational state snapshot on rate-limited decisions). | ✅ Implemented |
| **AU-3(1)** | Additional Audit Information | Duration of gate evaluation is captured per record. Session IDs link records within a proxy lifecycle. Server names identify which MCP backend was being proxied. | ✅ Implemented |
| **AU-8** | Time Stamps | Timestamps use `datetime.now(timezone.utc).isoformat()` — UTC with timezone designation. | ✅ Implemented |
| **AU-9** | Protection of Audit Information | The audit log file resides in a configurable path (default: `~/.config/agent-gate/audit.jsonl`). The vault directory — which is envelope-denied — protects vault manifests. However, the audit log file itself is not in the vault and could theoretically be modified by an agent with sufficient file system access. | ⚠️ Partial |
| **AU-9(3)** | Cryptographic Protection of Audit Information | SHA-256 hash chaining implemented.  Each audit record includes `prev_hash` (hash of previous record) and `record_hash` (hash of current record content), creating a tamper-evident chain from a deterministic genesis value.  `verify_chain()` walks the log and detects any modification, insertion, or deletion.  Records also include `policy_hash` binding each decision to the governing policy version.  Records are not yet signed with a cryptographic key. | ⚠️ Partial |
| **AU-10** | Non-repudiation | Partial.  Hash-chained audit records with `policy_hash` binding prove which policy version governed each decision, preventing retroactive policy modification from disguising the original authorization logic.  However, records are not digitally signed — the chain proves integrity (tampering is detectable) but not identity (cannot cryptographically prove who created the record). | ⚠️ Partial |
| **AU-11** | Audit Record Retention | Vault snapshots have configurable retention (`max_snapshots_per_file`, `max_age_days`). The audit log itself has no automated retention management. | ⚠️ Partial |

### Contingency Planning (CP)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **CP-9** | System Backup | Vault-backed rollback is the core safety mechanism. Every destructive action triggers a mandatory backup to the vault before the action proceeds. If the backup fails and policy specifies `on_failure: deny`, the destructive action is blocked. | ✅ Implemented |
| **CP-9(1)** | Testing for Reliability and Integrity | SHA-256 hashes are computed for every vault snapshot. The vault manifest (JSONL) records original path, vault path, timestamp, file size, and hash for each backup. Integrity can be verified by recomputing the hash. | ✅ Implemented |
| **CP-9(8)** | Cryptographic Protection of Backup Information | Vault snapshots are stored as plain copies with SHA-256 integrity hashes. Snapshots are not encrypted at rest. | ⚠️ Partial |
| **CP-10** | System Recovery and Reconstitution | The CLI (`agent_gate.cli`) provides `list`, `history`, `restore`, and `diff` commands for vault-based recovery. Restore is a file copy from the vault to the original location. Multiple snapshots of the same file provide point-in-time recovery options. | ✅ Implemented |

### Configuration Management (CM)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **CM-3** | Configuration Change Control | Every audit record includes `policy_hash`, a truncated SHA-256 hash of the governing policy bundle.  This creates a cryptographic binding between each authorization decision and the exact policy version that produced it.  Retroactive policy modifications cannot disguise the original authorization logic — the hash in historical records will not match the modified policy. | ✅ Implemented |
| **CM-7** | Least Functionality | Default-deny for unclassified actions means the agent can only execute commands explicitly classified in the policy.  The policy defines the complete set of allowed functionality. | ✅ Implemented |
| **CM-7(5)** | Authorized Software — Allowlisting | Literal-only argument enforcement functions as a command allowlist. Shell expansion syntax (`$VAR`, `$(cmd)`, backticks, globs) is rejected before classification — the gate defines what "clean" looks like and rejects anything else. | ✅ Implemented |

### System and Communications Protection (SC)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **SC-5** | Denial-of-Service Protection | Per-tool, per-tier, and global rate limits prevent agents from overwhelming target systems through rapid execution of allowed operations.  Sliding window counters enforce configurable call rates (e.g., `rm` at 10/minute, global at 200/minute).  Exponential backoff on repeated violations prevents tight retry loops from becoming a DoS vector.  The circuit breaker trips to read-only mode when failure rates exceed thresholds, halting cascading failures. | ✅ Implemented |
| **SC-7** | Boundary Protection | The MCP proxy is a protocol-level boundary enforcement point.  All MCP communication between client and server transits the proxy — there is no bypass path.  The proxy inspects `tools/call` messages and enforces policy at the protocol boundary. | ✅ Implemented |
| **SC-7(5)** | Deny by Default / Allow by Exception | Unclassified actions are denied by default.  Network actions require explicit policy enablement.  The agent must operate within declared boundaries, not outside them. | ✅ Implemented |

### System and Information Integrity (SI)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **SI-4** | System Monitoring | The audit log captures all tool calls with timing, verdicts, and tiers.  Sub-millisecond evaluation timing is recorded for performance monitoring.  The circuit breaker continuously monitors failure rates and slow call rates across a sliding window, automatically transitioning to protective states when thresholds are exceeded — this is automated system monitoring with automated response. | ✅ Implemented |
| **SI-10** | Information Input Validation | Tool call arguments are validated for literal-only content before classification.  The gate rejects shell expansion, variable references, command substitution, and glob patterns — ensuring the gate evaluates the same paths the shell would execute.  Rate limit context is validated before each action (remaining budget, breaker state, backoff status). | ✅ Implemented |
| **SI-17** | Fail-Safe Procedures | The three-state circuit breaker (CLOSED → OPEN → HALF_OPEN → CLOSED) implements fail-safe behavior.  When failure rates exceed the configured threshold, the system transitions to a known-safe state (read-only mode) rather than continuing to operate in degraded conditions.  HALF_OPEN probing enables automatic recovery without human intervention.  If vault backup fails and policy specifies `on_failure: deny`, destructive actions fail safe to denial. | ✅ Implemented |

---

## NIST AI Risk Management Framework 1.0 (AI RMF)

The AI RMF defines four functions: Govern, Map, Measure, and Manage. Agent Gate directly addresses subcategories within the Manage function, with supporting contributions to Govern and Measure.

### GOVERN

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **GV-1.1** | Legal and regulatory requirements involving AI are understood, managed, and documented | Agent Gate's policy-as-code approach makes authorization rules explicit, version-controlled, and auditable. YAML and Rego policies serve as machine-readable documentation of what the agent is and is not authorized to do. | ⚠️ Supportive |
| **GV-1.3** | Processes, procedures, and practices are in place to determine the needed level of risk management activities | Tiered classification (read-only → destructive → network → blocked) implements graduated risk management.  The tier determines the gate response: auto-allow, vault-backup-then-allow, escalate, or hard-deny. | ✅ Implemented |
| **GV-1.7** | Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risk or decrease the organization's trustworthiness | Rate limiting and circuit breaker provide operational risk management during AI agent execution.  Sliding window counters enforce tempo limits.  The circuit breaker automatically constrains agent operations when failure rates indicate degraded conditions, preventing cascading failures without requiring manual intervention. | ✅ Implemented |

### MAP

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **MP-2.3** | Scientific integrity and TEVV considerations are identified and documented | Agent Gate's test suite (220+ passing across eleven test suites) provides evidence of systematic verification.  Known limitations are documented in the README and this compliance mapping. | ⚠️ Supportive |

### MEASURE

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **MS-2.5** | The AI system is evaluated regularly for safety risks | Sub-millisecond gate evaluation timing recorded in every audit record enables performance regression detection.  The circuit breaker continuously evaluates safety risk through failure rate and slow call rate monitoring, automatically constraining agent operations when thresholds are exceeded.  Rate-limited decisions include `rate_context` snapshots for forensic analysis.  The OPA/Rego backend supports formal policy testing with `opa test` (including rate limit threshold tests). | ✅ Implemented |
| **MS-2.6** | AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment | Integration tests run against real MCP server implementations (12/12 passing against `@modelcontextprotocol/server-filesystem`). This tests the gate under conditions that match deployment. | ✅ Implemented |
| **MS-4.1** | Measurement approaches for identifying AI risks are connected to deployment context and informed by domain knowledge | The policy definition encodes deployment context: allowed paths define the workspace, denied paths protect sensitive directories, and tier definitions reflect the risk profile of specific commands in the deployment environment. | ✅ Implemented |

### MANAGE

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **MG-2.1** | Resources required to manage AI risks are taken into account | Agent Gate operates with zero additional infrastructure in its default configuration (Python backend, YAML policies). The OPA backend adds a single external dependency. This minimizes the resource burden of adding execution authority to an AI agent deployment. | ✅ Implemented |
| **MG-2.2** | Mechanisms are in place to determine if AI system risks exceed organizational risk tolerance | Escalation verdict returns tool calls that exceed the policy envelope to human operators with structured denial feedback, including the specific reason for denial and what would be required to proceed. | ✅ Implemented |
| **MG-2.4** | Mechanisms are in place and applied to sustain the value of deployed AI systems, including containment of impact | This is Agent Gate's core function.  Vault-backed rollback contains the impact of destructive actions.  Envelope enforcement contains the scope of agent operations.  Default-deny contains the risk of unknown actions.  Rate limiting and circuit breaker contain operational tempo, preventing runaway loops from overwhelming target systems.  The gate ensures that even authorized destructive actions are recoverable and that agent operations stay within sustainable operational parameters. | ✅ Implemented |
| **MG-3.1** | AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented | The MCP proxy operates transparently between client and server, monitoring all tool calls to third-party MCP servers. Every interaction is logged with the server name, enabling per-server risk analysis. | ✅ Implemented |
| **MG-3.2** | Pre-trained models are monitored as part of AI system regular monitoring | Not applicable — Agent Gate operates at the tool execution layer, not the model layer. It does not monitor model weights, training data, or inference behavior. | — |
| **MG-4.1** | Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and affected communities | The JSONL audit log provides a structured, machine-parseable record of every agent action and gate decision. This serves as the raw data for post-deployment monitoring and analysis. | ✅ Implemented |

---

## ISO/IEC 42001:2023 — AI Management System

ISO 42001 defines requirements for establishing and maintaining an AI management system. Agent Gate provides technical controls that support several clauses, but does not constitute an AIMS on its own.

| Clause | Requirement | Agent Gate Mapping | Status |
|---|---|---|---|
| **6.1.2** | AI risk assessment | Tiered classification is a risk assessment mechanism applied at the tool call level. Each action is assessed against policy and routed to the appropriate risk response. | ⚠️ Supportive |
| **6.1.3** | AI risk treatment | The six tiers (read-only, destructive, network, blocked, unclassified, rate-limited) define six risk treatment strategies: accept, mitigate-then-accept, escalate, avoid, escalate-with-default-deny, and tempo-constrain.  Rate limiting adds a treatment strategy where actions are individually acceptable but collectively risky at high velocity. | ⚠️ Supportive |
| **8.4** | AI system impact assessment | Vault-backed rollback bounds the impact of destructive actions. The audit log provides evidence for impact assessment after incidents. | ⚠️ Supportive |
| **9.1** | Monitoring, measurement, analysis and evaluation | Audit logging with sub-millisecond timing and structured records supports monitoring and measurement requirements. | ⚠️ Supportive |
| **A.6.2.6** | AI system operation and monitoring | The MCP proxy provides real-time operational monitoring of all agent-server interactions.  The circuit breaker continuously monitors failure rates and slow call rates, automatically transitioning to protective states when operational parameters degrade.  Rate-limited decisions include `rate_context` snapshots for operational analysis.  Every audit record includes `policy_hash` for configuration traceability. | ✅ Implemented |
| **A.10.3** | Sourcing of data | Not applicable — Agent Gate does not manage training data or data sourcing. | — |

---

## OMB Memorandum M-24-10 — Advancing Governance, Innovation, and Risk Management for Agency Use of AI

M-24-10 establishes requirements for federal agencies deploying AI. Agent Gate addresses several of the technical requirements for "safety-impacting" and "rights-impacting" AI systems.

| M-24-10 Requirement | Agent Gate Mapping | Status |
|---|---|---|
| **§5(c)(i)(A)** — Complete an AI impact assessment before deployment | Tiered classification and the policy definition process function as a structured impact assessment at the tool call level — defining what the agent can do, what requires backup, and what is prohibited. | ⚠️ Supportive |
| **§5(c)(i)(B)** — Conduct testing prior to deployment and on a regular basis | 220+ tests across eleven suites, including integration tests against real MCP servers.  OPA backend has formal Rego policy tests including rate limit threshold tests.  Test infrastructure is included in the repository for ongoing testing. | ✅ Implemented |
| **§5(c)(i)(D)** — Independently evaluate the AI before deployment | Agent Gate's enforcement is deterministic and fully testable. Policy evaluation can be independently verified by providing a tool call and confirming the expected verdict — no model inference or non-deterministic behavior is involved. | ✅ Implemented |
| **§5(c)(ii)(A)** — Implement adequate human oversight | Escalation verdict routes actions that exceed the policy envelope to human operators. Network actions default to escalation. Unclassified actions default to denial with instructions for human review. | ✅ Implemented |
| **§5(c)(ii)(B)** — Halt AI operations in cases of imminent risk | Blocked tier actions are unconditionally denied.  If the vault backup fails and policy specifies `on_failure: deny`, the destructive action is halted.  The circuit breaker automatically halts non-read operations when failure rates exceed configurable thresholds, transitioning the agent to read-only mode.  All halt mechanisms are deterministic — no confidence threshold or model judgment is involved. | ✅ Implemented |
| **§5(c)(iv)** — Maintain appropriate human oversight for consequential decisions | Agent Gate does not replace human oversight — it enforces boundaries within which the agent operates autonomously and escalates decisions that exceed those boundaries. The policy definition itself is the human oversight artifact: a human defines the authority envelope before the agent operates. | ✅ Implemented |

---

## Summary

| Framework | Controls Mapped | ✅ Implemented | ⚠️ Partial/Supportive | ❌ Gap |
|---|---|---|---|---|
| **SP 800-53** | 29 controls | 22 | 6 | 1 |
| **AI RMF** | 12 subcategories | 9 | 2 | 1 (n/a) |
| **ISO 42001** | 6 clauses | 1 | 4 | 1 (n/a) |
| **OMB M-24-10** | 5 requirements | 4 | 1 | 0 |

### Strongest Alignments

- **AC-3 (Access Enforcement)** — Agent Gate's core function is access enforcement at the tool execution boundary, now including dynamic enforcement via rate limits and circuit breaker.
- **CP-9 (System Backup)** — Vault-backed rollback is a direct, working implementation of pre-destruction backup.
- **SC-5 (Denial-of-Service Protection)** — Per-tool, per-tier, and global rate limits with circuit breaker prevent agents from overwhelming target systems.  Exponential backoff prevents retry loops.
- **SI-17 (Fail-Safe Procedures)** — Three-state circuit breaker transitions to known-safe state (read-only) when failure rates exceed thresholds.  Automatic recovery via HALF_OPEN probing.
- **CM-3 (Configuration Change Control)** — `policy_hash` on every audit record creates cryptographic binding between decisions and governing policy versions.
- **MG-2.4 (Containment of Impact)** — Envelope enforcement, vault backup, rate limiting, circuit breaker, and default-deny collectively bound the impact of agent operations.
- **M-24-10 §5(c)(ii)(B) (Halt Operations)** — Deterministic blocking of prohibited actions and automatic circuit breaker tripping with no model-in-the-loop uncertainty.

### Gaps Closed Since v0.1.0

- **AU-9(3) (Cryptographic audit protection)** — Was ❌ Gap, now ⚠️ Partial.  SHA-256 hash chaining implemented with `prev_hash`/`record_hash` and `verify_chain()`.  Policy hash binding on every record.  Remaining gap: records are not signed with a cryptographic key.
- **AU-10 (Non-repudiation)** — Was ❌ Gap, now ⚠️ Partial.  Hash-chained records with policy hash binding provide integrity evidence.  Remaining gap: no digital signature binding decisions to identity.

### Remaining Known Gaps

- **AC-3(7) (Role-based access control)** — No identity or role differentiation.  All agents are subject to the same policy.  This is also the largest gap in the AARM alignment (R6 Identity Binding).
- **AU-10 (Non-repudiation, full)** — Hash chaining proves integrity but not authorship.  Full non-repudiation requires cryptographic signing with identity-bound keys.

### Gaps Narrowed

- **AU-9(3)** — Hash chaining detects tampering, but records are not encrypted at rest or signed.  An attacker with file system access can detect that records were modified but could still replace the entire log.
- **MS-2.5** — Moved from ⚠️ Supportive to ✅ Implemented.  Circuit breaker provides continuous safety risk evaluation during execution, not just post-hoc analysis.

### Relationship to AARM

The [AARM Alignment Assessment](AARM_Alignment.md) covers Agent Gate's mapping to the Autonomous Action Runtime Management specification, which defines requirements specific to AI agent runtime security.  The rate limiting and circuit breaker implementation advanced AARM alignment on four requirements (R2, R3, R5, R8).  AARM and the frameworks in this document are complementary: AARM addresses *what an AI agent runtime security system must do*, while SP 800-53, AI RMF, ISO 42001, and M-24-10 address *how security and governance systems are evaluated in federal and enterprise contexts*.

---

## Changelog

### v0.2.0 (2026-02-23) — Rate Limiting & Circuit Breaker

Phase 5 implementation expanded compliance coverage significantly:

**New controls mapped:**
- **CM-3 (Configuration Change Control)** — `policy_hash` on every audit record ✅
- **SC-5 (Denial-of-Service Protection)** — Per-tool, per-tier, global rate limits with circuit breaker ✅
- **SI-17 (Fail-Safe Procedures)** — Three-state circuit breaker with automatic recovery ✅
- **GV-1.7 (Operational Risk Management)** — Rate limiting and circuit breaker as operational controls ✅

**Controls upgraded:**
- **AU-9(3)** — ❌ → ⚠️  Hash chaining implemented
- **AU-10** — ❌ → ⚠️  Policy hash provides partial non-repudiation
- **MS-2.5** — ⚠️ → ✅  Circuit breaker provides continuous safety evaluation
- **A.6.2.6** — ⚠️ → ✅  Circuit breaker and rate context provide operational monitoring

**Net effect:** SP 800-53 gaps reduced from 2 to 1.  Total implemented controls increased from 14 to 22 (across 29 controls, up from 20).

### v0.1.0 (2026-02-20) — Initial Mapping

Baseline compliance mapping.  20 SP 800-53 controls, 10 AI RMF subcategories, 6 ISO 42001 clauses, 5 M-24-10 requirements.

---

## References

- NIST SP 800-53 Rev. 5: [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- NIST AI Risk Management Framework 1.0: [https://www.nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)
- ISO/IEC 42001:2023: [https://www.iso.org/standard/81230.html](https://www.iso.org/standard/81230.html)
- OMB Memorandum M-24-10: [https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf](https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf)
- Agent Gate repository: [https://github.com/SeanFDZ/agent-gate](https://github.com/SeanFDZ/agent-gate)
