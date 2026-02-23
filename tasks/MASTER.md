# Phase 6: Identity Binding — Implementation Master Plan

**Version:** v0.3.0
**Target:** March 2026
**Prerequisite:** v0.2.0 (220+ tests passing, rate limiting, circuit breaker, policy hash)
**AARM:** R6 (Identity Binding) — ❌ Gap → ⚠️ Partial
**NIST:** AC-3(7) (RBAC) — ❌ Gap → ✅ Implemented

---

## Rules for All Agents

These rules are non-negotiable.  Every agent MUST follow them.

1. **Read before write.**  `cat` every file listed in "Before You Start" before writing a single line.  Confirm you understand the current structure.
2. **Never use `sed` for file editing.**  Use Python scripts, `str_replace`, or manual editing only.
3. **Double spaces after periods** in all comments, docstrings, and documentation.
4. **Commas instead of em dashes** in prose (comments, docstrings, docs).
5. **Python 3.9 compatibility.**  No `match` statements, no `type X = ...`, no `str | None` union syntax.  Use `Optional[str]` from typing.
6. **Imports use `agent_gate.` prefix.**  Example: `from agent_gate.identity import IdentityContext`.
7. **Backward compatibility is absolute.**  The `identity` section in YAML is optional.  Every existing test must pass without modification after every phase.  Existing policies without an `identity` section work identically to v0.2.0.
8. **Run ALL tests after every phase.**  Command: `cd /path/to/repo && python -m pytest -x -q`.  All 220+ existing tests plus new tests must pass.
9. **No new external dependencies.**  Identity binding uses stdlib only (os, re, json, dataclasses).
10. **One commit per phase.**  Commit message format: `Phase 6.X: <description>`.

---

## Architecture Overview

### Identity Flow

```
Environment/Config/MCP Metadata
        │
        ▼
┌──────────────────┐
│  IdentityContext  │  ← identity.py (NEW)
│  operator         │
│  agent_id         │
│  service_account  │
│  session_id       │
│  role             │
└──────────────────┘
        │
        ├──► policy_loader.py  (role → override merge)
        ├──► gate.py           (propagate through pipeline)
        ├──► audit.py          (bind to every record)
        ├──► opa_classifier.py (pass as input.identity)
        ├──► yaml_to_rego.py   (compile role overrides)
        └──► mcp_proxy.py      (resolve at startup)
```

### AARM R6 Five Identity Levels

| AARM Level | Agent Gate Field | Source |
|---|---|---|
| Human identity | `operator` | `AGENT_GATE_OPERATOR` env var or config |
| Service identity | `service_account` | `AGENT_GATE_SERVICE` env var or config |
| Agent identity | `agent_id` | `AGENT_GATE_AGENT_ID` env var or config |
| Session identity | `session_id` | Generated UUID (already exists in mcp_proxy) |
| Role/privilege scope | `role` | `AGENT_GATE_ROLE` env var or config → RBAC |

### YAML Schema Addition

```yaml
# Optional section — omit for uniform policy (backward compatible)
identity:
  source: "environment"  # "environment" | "config" | "mcp_metadata" | "header"

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

### OPA Input Document Extension

```json
{
  "command": "rm",
  "args": ["-f", "old.txt"],
  "target_paths": ["/workspace/old.txt"],
  "tool": "bash",
  "raw_input": {},
  "envelope": { ... },
  "rate_context": { ... },
  "identity": {
    "operator": "sean",
    "agent_id": "claude-code-001",
    "service_account": "ci-pipeline",
    "session_id": "a1b2c3d4",
    "role": "admin"
  }
}
```

### OPA RBAC Pattern

```rego
# Role-based override: admin gets network access
decision := result if {
    all_paths_in_envelope
    input.identity.role == "admin"
    some name, pattern in network_result
    result := {
        "tier": "network",
        "reason": "Network action allowed for admin role",
        ...
    }
}
```

---

## Phase Dependency Graph

```
Phase 6.1 (identity.py)
    │
    ▼
Phase 6.2 (policy_loader.py)
    │
    ├──────────┬──────────┐
    ▼          ▼          ▼
Phase 6.3  Phase 6.4  Phase 6.5
(gate.py)  (audit.py) (opa + rego)
    │          │          │
    └──────────┴──────────┘
               │
               ▼
         Phase 6.6
       (mcp_proxy.py)
               │
               ▼
         Phase 6.7
       (documentation)
```

**Parallelizable after Phase 6.2:**
- Phases 6.3, 6.4, 6.5 can run in parallel (different files, no conflicts)
- Phase 6.6 depends on 6.1 + 6.3 + 6.4
- Phase 6.7 depends on all prior phases

---

## Phase Summary

| Phase | File | Task | New Tests |
|---|---|---|---|
| 6.1 | `identity.py` | Identity resolver module | ~15 |
| 6.2 | `policy_loader.py` | Parse identity section, validate roles, merge overrides | ~20 |
| 6.3 | `gate.py` | Accept identity, propagate through pipeline, apply role overrides | ~15 |
| 6.4 | `audit.py` | Add identity fields to AuditRecord | ~10 |
| 6.5 | `opa_classifier.py`, `yaml_to_rego.py` | Pass identity to OPA, compile RBAC rules | ~15 |
| 6.6 | `mcp_proxy.py` | Resolve identity at startup, propagate to gate and audit | ~10 |
| 6.7 | Docs | Update AARM_Alignment.md, COMPLIANCE.md, README.md, ROADMAP.md | 0 |

**Estimated total new tests:** ~85
**Estimated total after phase:** ~305

---

## Research Summary

### MCP Protocol Identity State (as of Feb 2026)

The MCP specification has evolved significantly on identity:
- **stdio transport** (Agent Gate's current mode): No built-in authentication.  Identity must come from environment or configuration.
- **Streamable HTTP transport**: Full OAuth 2.1 support with CIMD (Client ID Metadata Documents) and Cross App Access (XAA) for enterprise SSO.
- **Implication for Agent Gate:** For v0.3.0, environment/config-based identity is the correct approach for stdio.  MCP metadata extraction becomes relevant when Agent Gate supports HTTP transport in a future version.

### OPA RBAC Patterns

Standard OPA RBAC passes identity as part of `input`:
```json
{"input": {"user": "alice", "role": "admin", "action": "write", ...}}
```

Rego evaluates:
```rego
allow if {
    input.role == "admin"
    input.action == "write"
}
```

Agent Gate's approach: pass `input.identity` containing all five AARM levels.  Rego rules can then differentiate by any identity field.

### AARM R6 Conformance Target

After Phase 6, Agent Gate will satisfy 4 of 5 AARM R6 identity levels:
- ✅ Human (operator)
- ✅ Service (service_account)
- ✅ Agent (agent_id)
- ✅ Session (session_id — already exists)
- ⚠️ Role/privilege (RBAC via config/env — not yet integrated with external IdP)

This moves R6 from ❌ Gap to ⚠️ Partial, which is the target stated in ROADMAP.md.
