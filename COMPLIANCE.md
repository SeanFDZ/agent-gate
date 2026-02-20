# Compliance Framework Mapping — Agent Gate

**Document version:** 0.1.0
**Agent Gate version:** 0.1.0
**Date:** 2026-02-20
**Status:** Implementation mapping — this is NOT a certification or accreditation claim

---

## Overview

This document maps Agent Gate's implemented capabilities to controls and requirements in established security, AI governance, and federal policy frameworks. The goal is transparency: showing which controls Agent Gate directly supports, which it partially addresses, and where gaps remain.

Agent Gate is an execution authority layer — it intercepts AI agent tool calls before execution and enforces policy-based authorization with vault-backed rollback. It does not replace a complete security program, identity management system, or organizational AI governance framework. It addresses a specific and critical gap: controlling what AI agents *do* before they do it.

For alignment with the Autonomous Action Runtime Management (AARM) specification, see [AARM_Alignment.md](AARM_Alignment.md).

---

## NIST SP 800-53 Rev. 5 — Security and Privacy Controls

SP 800-53 defines the security control catalog used across federal systems. Agent Gate maps to controls in several families. Each mapping references the specific implementation mechanism.

### Access Control (AC)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **AC-3** | Access Enforcement | Gate evaluates every tool call against policy before execution. The `Gate.evaluate()` method is the enforcement function — no tool call reaches execution without passing through it. Tiered classification (read-only, destructive, network, blocked, unclassified) implements differentiated access decisions. | ✅ Implemented |
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
| **AU-3** | Content of Audit Records | Each record contains: timestamp (ISO 8601), tool name, arguments, verdict, tier, reason, server name, session ID, message ID, vault path (if applicable), and gate evaluation duration in milliseconds. | ✅ Implemented |
| **AU-3(1)** | Additional Audit Information | Duration of gate evaluation is captured per record. Session IDs link records within a proxy lifecycle. Server names identify which MCP backend was being proxied. | ✅ Implemented |
| **AU-8** | Time Stamps | Timestamps use `datetime.now(timezone.utc).isoformat()` — UTC with timezone designation. | ✅ Implemented |
| **AU-9** | Protection of Audit Information | The audit log file resides in a configurable path (default: `~/.config/agent-gate/audit.jsonl`). The vault directory — which is envelope-denied — protects vault manifests. However, the audit log file itself is not in the vault and could theoretically be modified by an agent with sufficient file system access. | ⚠️ Partial |
| **AU-9(3)** | Cryptographic Protection of Audit Information | Not implemented. Audit records are not cryptographically signed or hash-chained. An attacker or misconfigured agent with file system access could modify the log without detection. | ❌ Gap |
| **AU-10** | Non-repudiation | Not implemented. No digital signature binds a decision to an identity. The audit log records what happened, but cannot cryptographically prove who authorized it. | ❌ Gap |
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
| **CM-7** | Least Functionality | Default-deny for unclassified actions means the agent can only execute commands explicitly classified in the policy. The policy defines the complete set of allowed functionality. | ✅ Implemented |
| **CM-7(5)** | Authorized Software — Allowlisting | Literal-only argument enforcement functions as a command allowlist. Shell expansion syntax (`$VAR`, `$(cmd)`, backticks, globs) is rejected before classification — the gate defines what "clean" looks like and rejects anything else. | ✅ Implemented |

### System and Communications Protection (SC)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **SC-7** | Boundary Protection | The MCP proxy is a protocol-level boundary enforcement point. All MCP communication between client and server transits the proxy — there is no bypass path. The proxy inspects `tools/call` messages and enforces policy at the protocol boundary. | ✅ Implemented |
| **SC-7(5)** | Deny by Default / Allow by Exception | Unclassified actions are denied by default. Network actions require explicit policy enablement. The agent must operate within declared boundaries, not outside them. | ✅ Implemented |

### System and Information Integrity (SI)

| Control | Title | Agent Gate Mapping | Status |
|---|---|---|---|
| **SI-4** | System Monitoring | The audit log captures all tool calls with timing, verdicts, and tiers. Sub-millisecond evaluation timing is recorded for performance monitoring. | ✅ Implemented |
| **SI-10** | Information Input Validation | Tool call arguments are validated for literal-only content before classification. The gate rejects shell expansion, variable references, command substitution, and glob patterns — ensuring the gate evaluates the same paths the shell would execute. | ✅ Implemented |

---

## NIST AI Risk Management Framework 1.0 (AI RMF)

The AI RMF defines four functions: Govern, Map, Measure, and Manage. Agent Gate directly addresses subcategories within the Manage function, with supporting contributions to Govern and Measure.

### GOVERN

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **GV-1.1** | Legal and regulatory requirements involving AI are understood, managed, and documented | Agent Gate's policy-as-code approach makes authorization rules explicit, version-controlled, and auditable. YAML and Rego policies serve as machine-readable documentation of what the agent is and is not authorized to do. | ⚠️ Supportive |
| **GV-1.3** | Processes, procedures, and practices are in place to determine the needed level of risk management activities | Tiered classification (read-only → destructive → network → blocked) implements graduated risk management. The tier determines the gate response: auto-allow, vault-backup-then-allow, escalate, or hard-deny. | ✅ Implemented |

### MAP

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **MP-2.3** | Scientific integrity and TEVV considerations are identified and documented | Agent Gate's test suite (219/219 passing across eight test suites) provides evidence of systematic verification. Known limitations are documented in the README and this compliance mapping. | ⚠️ Supportive |

### MEASURE

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **MS-2.5** | The AI system is evaluated regularly for safety risks | Sub-millisecond gate evaluation timing recorded in every audit record enables performance regression detection. The OPA/Rego backend supports formal policy testing with `opa test` (24/24 Rego tests passing). | ⚠️ Supportive |
| **MS-2.6** | AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment | Integration tests run against real MCP server implementations (12/12 passing against `@modelcontextprotocol/server-filesystem`). This tests the gate under conditions that match deployment. | ✅ Implemented |
| **MS-4.1** | Measurement approaches for identifying AI risks are connected to deployment context and informed by domain knowledge | The policy definition encodes deployment context: allowed paths define the workspace, denied paths protect sensitive directories, and tier definitions reflect the risk profile of specific commands in the deployment environment. | ✅ Implemented |

### MANAGE

| Subcategory | Description | Agent Gate Mapping | Status |
|---|---|---|---|
| **MG-2.1** | Resources required to manage AI risks are taken into account | Agent Gate operates with zero additional infrastructure in its default configuration (Python backend, YAML policies). The OPA backend adds a single external dependency. This minimizes the resource burden of adding execution authority to an AI agent deployment. | ✅ Implemented |
| **MG-2.2** | Mechanisms are in place to determine if AI system risks exceed organizational risk tolerance | Escalation verdict returns tool calls that exceed the policy envelope to human operators with structured denial feedback, including the specific reason for denial and what would be required to proceed. | ✅ Implemented |
| **MG-2.4** | Mechanisms are in place and applied to sustain the value of deployed AI systems, including containment of impact | This is Agent Gate's core function. Vault-backed rollback contains the impact of destructive actions. Envelope enforcement contains the scope of agent operations. Default-deny contains the risk of unknown actions. The gate ensures that even authorized destructive actions are recoverable. | ✅ Implemented |
| **MG-3.1** | AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented | The MCP proxy operates transparently between client and server, monitoring all tool calls to third-party MCP servers. Every interaction is logged with the server name, enabling per-server risk analysis. | ✅ Implemented |
| **MG-3.2** | Pre-trained models are monitored as part of AI system regular monitoring | Not applicable — Agent Gate operates at the tool execution layer, not the model layer. It does not monitor model weights, training data, or inference behavior. | — |
| **MG-4.1** | Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and affected communities | The JSONL audit log provides a structured, machine-parseable record of every agent action and gate decision. This serves as the raw data for post-deployment monitoring and analysis. | ✅ Implemented |

---

## ISO/IEC 42001:2023 — AI Management System

ISO 42001 defines requirements for establishing and maintaining an AI management system. Agent Gate provides technical controls that support several clauses, but does not constitute an AIMS on its own.

| Clause | Requirement | Agent Gate Mapping | Status |
|---|---|---|---|
| **6.1.2** | AI risk assessment | Tiered classification is a risk assessment mechanism applied at the tool call level. Each action is assessed against policy and routed to the appropriate risk response. | ⚠️ Supportive |
| **6.1.3** | AI risk treatment | The five tiers (read-only, destructive, network, blocked, unclassified) define five risk treatment strategies: accept, mitigate-then-accept, escalate, avoid, and escalate-with-default-deny. | ⚠️ Supportive |
| **8.4** | AI system impact assessment | Vault-backed rollback bounds the impact of destructive actions. The audit log provides evidence for impact assessment after incidents. | ⚠️ Supportive |
| **9.1** | Monitoring, measurement, analysis and evaluation | Audit logging with sub-millisecond timing and structured records supports monitoring and measurement requirements. | ⚠️ Supportive |
| **A.6.2.6** | AI system operation and monitoring | The MCP proxy provides real-time operational monitoring of all agent-server interactions. | ⚠️ Supportive |
| **A.10.3** | Sourcing of data | Not applicable — Agent Gate does not manage training data or data sourcing. | — |

---

## OMB Memorandum M-24-10 — Advancing Governance, Innovation, and Risk Management for Agency Use of AI

M-24-10 establishes requirements for federal agencies deploying AI. Agent Gate addresses several of the technical requirements for "safety-impacting" and "rights-impacting" AI systems.

| M-24-10 Requirement | Agent Gate Mapping | Status |
|---|---|---|
| **§5(c)(i)(A)** — Complete an AI impact assessment before deployment | Tiered classification and the policy definition process function as a structured impact assessment at the tool call level — defining what the agent can do, what requires backup, and what is prohibited. | ⚠️ Supportive |
| **§5(c)(i)(B)** — Conduct testing prior to deployment and on a regular basis | 219/219 tests across eight suites, including integration tests against real MCP servers. OPA backend has 24/24 Rego policy tests. Test infrastructure is included in the repository for ongoing testing. | ✅ Implemented |
| **§5(c)(i)(D)** — Independently evaluate the AI before deployment | Agent Gate's enforcement is deterministic and fully testable. Policy evaluation can be independently verified by providing a tool call and confirming the expected verdict — no model inference or non-deterministic behavior is involved. | ✅ Implemented |
| **§5(c)(ii)(A)** — Implement adequate human oversight | Escalation verdict routes actions that exceed the policy envelope to human operators. Network actions default to escalation. Unclassified actions default to denial with instructions for human review. | ✅ Implemented |
| **§5(c)(ii)(B)** — Halt AI operations in cases of imminent risk | Blocked tier actions are unconditionally denied. If the vault backup fails and policy specifies `on_failure: deny`, the destructive action is halted. These are deterministic — no confidence threshold or model judgment is involved in the halt decision. | ✅ Implemented |
| **§5(c)(iv)** — Maintain appropriate human oversight for consequential decisions | Agent Gate does not replace human oversight — it enforces boundaries within which the agent operates autonomously and escalates decisions that exceed those boundaries. The policy definition itself is the human oversight artifact: a human defines the authority envelope before the agent operates. | ✅ Implemented |

---

## Summary

| Framework | Controls Mapped | ✅ Implemented | ⚠️ Partial/Supportive | ❌ Gap |
|---|---|---|---|---|
| **SP 800-53** | 20 controls | 14 | 4 | 2 |
| **AI RMF** | 10 subcategories | 6 | 3 | 1 (n/a) |
| **ISO 42001** | 6 clauses | 0 | 5 | 1 (n/a) |
| **OMB M-24-10** | 5 requirements | 4 | 1 | 0 |

### Strongest Alignments

- **AC-3 (Access Enforcement)** — Agent Gate's core function is access enforcement at the tool execution boundary.
- **CP-9 (System Backup)** — Vault-backed rollback is a direct, working implementation of pre-destruction backup.
- **MG-2.4 (Containment of Impact)** — Envelope enforcement, vault backup, and default-deny collectively bound the impact of agent operations.
- **M-24-10 §5(c)(ii)(B) (Halt Operations)** — Deterministic blocking of prohibited actions with no model-in-the-loop uncertainty.

### Known Gaps

- **AU-9(3) / AU-10 (Cryptographic audit protection and non-repudiation)** — Audit records are not signed or hash-chained. This is the most impactful gap for compliance posture.
- **AC-3(7) (Role-based access control)** — No identity or role differentiation. All agents are subject to the same policy.

### Relationship to AARM

The [AARM Alignment Assessment](AARM_Alignment.md) covers Agent Gate's mapping to the Autonomous Action Runtime Management specification, which defines requirements specific to AI agent runtime security. AARM and the frameworks in this document are complementary: AARM addresses *what an AI agent runtime security system must do*, while SP 800-53, AI RMF, ISO 42001, and M-24-10 address *how security and governance systems are evaluated in federal and enterprise contexts*.

---

## References

- NIST SP 800-53 Rev. 5: [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- NIST AI Risk Management Framework 1.0: [https://www.nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)
- ISO/IEC 42001:2023: [https://www.iso.org/standard/81230.html](https://www.iso.org/standard/81230.html)
- OMB Memorandum M-24-10: [https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf](https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf)
- Agent Gate repository: [https://github.com/SeanFDZ/agent-gate](https://github.com/SeanFDZ/agent-gate)
