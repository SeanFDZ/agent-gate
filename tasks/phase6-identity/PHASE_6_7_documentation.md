# Phase 6.7: Documentation Updates

**Files:** `AARM_Alignment.md`, `COMPLIANCE.md`, `README.md`, `ROADMAP.md`
**Depends on:** All prior phases (6.1–6.6) must be complete
**Parallel:** None (final phase)

---

## Before You Start

```bash
cat AARM_Alignment.md    # Current AARM gap analysis
cat COMPLIANCE.md        # Current NIST SP 800-53 mapping
cat README.md            # Current project overview
cat ROADMAP.md           # Current roadmap
```

---

## Context

Documentation ships with the code.  This phase updates all compliance and architecture docs to reflect the new identity binding capability.  The updates must be honest — identity is environment/config-based, not IdP-integrated.  This moves R6 from ❌ Gap to ⚠️ Partial, not to ✅ Satisfied.

---

## Deliverables

### 1. `AARM_Alignment.md`

Update the R6 section:

```markdown
#### R6: Identity Binding ⚠️ Partial

> *Requirement: Bind actions to identity at five levels — human,
> service, agent, session, and role/privilege scope.*

Agent Gate v0.3.0 implements environment/config-based identity
binding at four of five AARM identity levels, with role-based
policy differentiation (RBAC).

| AARM Identity Level | Agent Gate Status |
|---|---|
| Human identity | ⚠️ `operator` field — environment variable or config |
| Service identity | ⚠️ `service_account` field — environment variable or config |
| Agent identity | ⚠️ `agent_id` field — environment variable or config |
| Session identity | ✅ UUID-based `session_id` — auto-generated per session |
| Role/privilege scope | ⚠️ `role` field — drives RBAC policy differentiation |

**Implementation evidence:**
- `identity.py`: `IdentityContext` frozen dataclass with five fields
  mapping to AARM identity levels
- `identity.py`: `resolve_identity()` resolves from YAML config
  (${VAR} references), environment variables, or defaults
- `policy_loader.py`: `identity.roles` section defines per-role
  overrides for rate limits, gate behavior, and envelope
- `gate.py`: Role overrides applied to rate limits and gate behavior
  at initialization; identity propagated through all decisions
- `audit.py`: `operator`, `agent_id`, `service_account`, `role`
  fields on every AuditRecord
- `opa_classifier.py`: `input.identity` in OPA input document
  enables attribute-based decisions in Rego
- `yaml_to_rego.py`: Generates RBAC Rego rules from role definitions
- `mcp_proxy.py`: Identity resolved at proxy startup, propagated
  to gate and audit

**Remaining gap:** Identity claims come from environment variables
and configuration, not from authenticated identity providers
(OAuth/OIDC, mTLS, API key validation).  The operator who
configures the environment is trusted to provide accurate identity.
Full R6 satisfaction requires integration with external IdP for
cryptographic identity verification.

**What this enables:**
- Multi-agent policy differentiation (admin vs. restricted)
- Audit records that answer "who authorized this?"
- Foundation for JIT authority grants (R9)
- Foundation for signed receipts with identity binding (R5)
```

Update the summary table:

```markdown
| **R6** | MUST | Identity binding | ⚠️ Partial | Environment/config-based identity at 4 of 5 levels; RBAC via role-based policy overrides |
```

Update the Core status line:

```markdown
**AARM Core (R1–R6):** 1 of 6 fully satisfied.  5 of 6 partially satisfied.  0 gaps.
```

Update the Path to Core Conformance section:

```markdown
### 5. Identity Binding (R6) — Partially Implemented

v0.3.0 implements environment/config-based identity binding with
RBAC policy differentiation.  Remaining work for full R6:

- Integration with OAuth/OIDC for authenticated human identity
- mTLS certificate validation for service identity
- MCP protocol metadata extraction when HTTP transport is supported
- JIT authority grants scoped to identity (AARM R9 prerequisite)
```

### 2. `COMPLIANCE.md`

Update AC-3(7) from ❌ to ✅:

```markdown
| **AC-3(7)** | Role-Based Access Control | Identity roles defined
in policy YAML with per-role overrides for rate limits, gate
behavior (action tier handling), and envelope restrictions.
RBAC evaluation in both Python and OPA backends.  Role resolved
from environment or configuration at gate initialization.
| ✅ Implemented |
```

Update AU-10:

```markdown
| **AU-10** | Non-Repudiation | Hash-chained audit records with
policy hash binding AND identity binding (operator, agent_id,
service_account, role on every record).  Identity fields included
in record hash, providing tamper evidence for identity claims.
Still needs cryptographic signing for full non-repudiation.
| ⚠️ Improved |
```

Add new controls if applicable:

```markdown
| **IA-2** | Identification and Authentication | Identity context
resolved from environment/config at startup.  Identity claims
propagated through evaluation pipeline and bound to audit records.
Not yet authenticated against external IdP.
| ⚠️ Partial |

| **IA-4** | Identifier Management | Unique session_id
auto-generated per gate/proxy lifecycle.  operator, agent_id,
and service_account identifiers configurable via environment
or policy.  | ⚠️ Partial |
```

### 3. `README.md`

Add Identity Binding to the feature list and architecture section.

In the architecture diagram or description, add identity flow.

Add a "Configuration: Identity" section:

```markdown
### Identity Binding (v0.3.0)

Agent Gate supports identity-aware policy enforcement via
environment variables or policy configuration:

```bash
# Set identity via environment
export AGENT_GATE_OPERATOR="sean"
export AGENT_GATE_ROLE="admin"
export AGENT_GATE_AGENT_ID="claude-code-001"
```

Or via policy YAML:

```yaml
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
        network:
          behavior: "allow"
    restricted:
      rate_limits:
        global: { max_calls: 50, window_seconds: 60 }
```

Identity is included in every audit record and available to
OPA policies via `input.identity` for attribute-based decisions.
```

### 4. `ROADMAP.md`

Update the Phase 6 status:

```markdown
## Phase 6: Identity Binding (v0.3.0)

**Target:** March 2026  ← ✅ Implemented
```

Update the Version Plan table:

```markdown
| **v0.3.0** | Identity | Identity binding, RBAC, role-based policy overrides | ✅ Released YYYY-MM-DD |
```

Update the AARM Conformance Trajectory and NIST Gap Trajectory tables.

---

## Test Cases

No new tests.  Documentation changes only.

---

## Verification

```bash
# Final full test run
python -m pytest -x -q
# Expected: ~305 tests passing (220 existing + ~85 new)

# Verify doc links and formatting
# Manual review of all four documents
```

---

## Commit

```
Phase 6.7: Documentation updates for v0.3.0 identity binding

- AARM_Alignment.md: R6 updated from Gap to Partial
- COMPLIANCE.md: AC-3(7) updated from Gap to Implemented
- README.md: Identity binding section added
- ROADMAP.md: Phase 6 marked complete
- AARM Core: 0 gaps remaining (1 satisfied, 5 partial)
- NIST SP 800-53: 0 gaps remaining
```
