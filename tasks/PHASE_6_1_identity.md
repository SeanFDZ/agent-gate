# Phase 6.1: Identity Resolver Module

**File:** `identity.py` (NEW)
**Depends on:** Nothing (standalone new module)
**Parallel:** This is the first phase.  Nothing else starts until this passes.

---

## Before You Start

Read these files to understand the patterns and conventions:

```bash
cat policy_loader.py    # Understand variable resolution pattern (${VAR})
cat gate.py             # Understand how Gate __init__ accepts config
cat audit.py            # Understand AuditRecord dataclass pattern
cat mcp_proxy.py        # See existing session_id generation
cat classifier_base.py  # See dataclass conventions
```

---

## Context

Agent Gate needs a single, well-defined identity context object that flows through the entire system.  This module resolves identity from multiple sources (environment variables, explicit config, MCP metadata) and produces an immutable `IdentityContext` dataclass.

The identity resolver does NOT authenticate.  It collects identity claims from trusted sources (the environment the operator configured, the config file the operator wrote).  Authentication is the operator's responsibility.  Agent Gate's job is to propagate and enforce based on whatever identity is provided.

This is architecturally identical to how PALs don't verify that the President made a good decision — they verify that the correct codes are present.

---

## Deliverables

### `identity.py`

```python
# Module: agent_gate/identity.py

# Classes:
@dataclass(frozen=True)
class IdentityContext:
    """
    Immutable identity context for a gate session.

    Maps to the five AARM R6 identity levels:
      - operator:        Human who launched/authorized the agent
      - agent_id:        Unique identifier for this agent instance
      - service_account: Service-level identity (CI pipeline, deployment system)
      - session_id:      Unique session identifier (auto-generated if not provided)
      - role:            Role for RBAC policy differentiation

    All fields are Optional[str].  An absent field means that
    identity level is not bound for this session.  The gate
    still functions — it just can't differentiate by that level.
    """
    operator: Optional[str] = None
    agent_id: Optional[str] = None
    service_account: Optional[str] = None
    session_id: Optional[str] = None
    role: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dict, omitting None values."""

    def has_identity(self) -> bool:
        """Return True if any identity field is set (besides session_id)."""

    @property
    def display_name(self) -> str:
        """Human-readable identity summary for logging."""


def resolve_identity(
    identity_config: Optional[dict] = None,
    session_id: Optional[str] = None,
) -> IdentityContext:
    """
    Resolve identity from configuration and environment.

    Resolution order per field:
      1. Explicit identity_config dict (from parsed YAML identity.fields)
      2. Environment variables (AGENT_GATE_OPERATOR, etc.)
      3. Defaults (session_id auto-generated if not provided)

    The identity_config values may contain ${ENV_VAR} references
    which are resolved against the environment.

    Args:
        identity_config: Parsed identity.fields from policy YAML.
            Values may be literal strings or ${ENV_VAR} references.
        session_id: Pre-existing session ID (from MCP proxy).
            If provided, takes precedence over config/env.

    Returns:
        Frozen IdentityContext with all resolvable fields set.
    """


def _resolve_field(
    field_name: str,
    config_value: Optional[str],
    env_var: str,
) -> Optional[str]:
    """
    Resolve a single identity field.

    Priority:
      1. config_value (if not None and not empty after env resolution)
      2. os.environ.get(env_var)
      3. None

    If config_value contains ${VAR}, resolve against os.environ.
    """
```

### Environment Variable Mapping

| Field | Environment Variable | YAML Config Key |
|---|---|---|
| operator | `AGENT_GATE_OPERATOR` | `identity.fields.operator` |
| agent_id | `AGENT_GATE_AGENT_ID` | `identity.fields.agent_id` |
| service_account | `AGENT_GATE_SERVICE` | `identity.fields.service_account` |
| session_id | `AGENT_GATE_SESSION` | `identity.fields.session_id` |
| role | `AGENT_GATE_ROLE` | `identity.fields.role` |

---

## Test Cases

### File: `test_identity.py` (NEW)

```
test_empty_identity_all_none
    resolve_identity() with no config, no env vars
    → all fields None except session_id (auto-generated UUID)

test_env_var_resolution
    Set AGENT_GATE_OPERATOR="sean", AGENT_GATE_ROLE="admin"
    resolve_identity() with no config
    → operator="sean", role="admin"

test_config_literal_values
    resolve_identity({"operator": "sean", "role": "admin"})
    → operator="sean", role="admin"

test_config_env_var_references
    Set AGENT_GATE_OPERATOR="sean"
    resolve_identity({"operator": "${AGENT_GATE_OPERATOR}"})
    → operator="sean"

test_config_overrides_env
    Set AGENT_GATE_OPERATOR="env_user"
    resolve_identity({"operator": "config_user"})
    → operator="config_user" (config takes precedence)

test_unresolved_env_var_becomes_none
    resolve_identity({"operator": "${NONEXISTENT_VAR}"})
    → operator=None (unresolvable reference → None)

test_session_id_preserved
    resolve_identity(session_id="abc123")
    → session_id="abc123"

test_session_id_auto_generated
    resolve_identity()
    → session_id is a non-empty string (UUID format)

test_session_id_param_overrides_config
    resolve_identity({"session_id": "from_config"}, session_id="from_param")
    → session_id="from_param"

test_frozen_dataclass
    ctx = resolve_identity({"operator": "sean"})
    Attempt ctx.operator = "other"
    → raises FrozenInstanceError

test_to_dict_omits_none
    ctx = IdentityContext(operator="sean", role="admin")
    ctx.to_dict() → {"operator": "sean", "role": "admin"}

test_to_dict_includes_session
    ctx = IdentityContext(session_id="abc")
    ctx.to_dict() → {"session_id": "abc"}

test_has_identity_true
    ctx = IdentityContext(operator="sean")
    ctx.has_identity() → True

test_has_identity_false_session_only
    ctx = IdentityContext(session_id="abc")
    ctx.has_identity() → False (session_id alone doesn't count)

test_display_name_with_operator
    ctx = IdentityContext(operator="sean", role="admin")
    ctx.display_name → "sean (role=admin)"

test_display_name_anonymous
    ctx = IdentityContext()
    ctx.display_name → "anonymous"
```

---

## Verification

```bash
# Run just the new tests
python -m pytest test_identity.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all 220+ existing tests pass, ~15 new tests pass
```

---

## Commit

```
Phase 6.1: Identity resolver module

New module: identity.py
- IdentityContext frozen dataclass (five AARM R6 identity levels)
- resolve_identity() resolves from config, env vars, or defaults
- Environment variable resolution for ${VAR} references
- Auto-generated session_id when not provided
- 15 new tests in test_identity.py
```
