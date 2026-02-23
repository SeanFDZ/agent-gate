# Phase 6.2: Policy Loader — Identity Section & Role Overrides

**File:** `policy_loader.py`
**Depends on:** Phase 6.1 (identity.py must exist)
**Parallel:** Nothing else depends on this except 6.3-6.7

---

## Before You Start

```bash
cat policy_loader.py      # Current validation and resolution logic
cat identity.py           # Phase 6.1 output — IdentityContext
cat default.yaml          # Current YAML schema
cat gate.py               # How Gate.__init__ calls load_policy
cat test_policy_loader_rates.py  # Existing validation test patterns
cat test_gate.py          # How policies are loaded in tests
```

---

## Context

The policy loader needs three additions:

1. **Parse the optional `identity` section** from YAML (source, fields, roles).
2. **Validate the identity section** — valid source values, well-formed role definitions, role names don't conflict with reserved words.
3. **Provide a `merge_role_overrides()` method** that takes an `IdentityContext` and returns a Policy with role-specific overrides applied.  This is called at gate evaluation time, NOT at load time, because the identity may change between sessions.

The identity section is 100% optional.  If omitted, the Policy object behaves identically to v0.2.0.  All existing tests pass without modification.

---

## Deliverables

### `policy_loader.py` Changes

```python
class Policy:
    # Add to __init__ after existing attributes:
    self.identity_config = self._raw.get("identity", {})
    self.identity_fields = self.identity_config.get("fields", {})
    self.identity_source = self.identity_config.get("source", "environment")
    self.identity_roles = self.identity_config.get("roles", {})

    # Add validation in _validate():
    if "identity" in self._raw:
        self._validate_identity()

    def _validate_identity(self):
        """Validate the optional identity section."""
        identity = self._raw["identity"]
        if not isinstance(identity, dict):
            raise PolicyValidationError(
                "identity must be a mapping"
            )

        # Validate source
        valid_sources = {"environment", "config", "mcp_metadata", "header"}
        source = identity.get("source", "environment")
        if source not in valid_sources:
            raise PolicyValidationError(
                f"identity.source must be one of {valid_sources}, "
                f"got '{source}'"
            )

        # Validate fields (if present)
        fields = identity.get("fields", {})
        if not isinstance(fields, dict):
            raise PolicyValidationError(
                "identity.fields must be a mapping"
            )
        valid_field_names = {
            "operator", "agent_id", "service_account",
            "session_id", "role"
        }
        for key in fields:
            if key not in valid_field_names:
                raise PolicyValidationError(
                    f"identity.fields.{key} is not a recognized "
                    f"identity field.  Valid: {valid_field_names}"
                )

        # Validate roles (if present)
        roles = identity.get("roles", {})
        if not isinstance(roles, dict):
            raise PolicyValidationError(
                "identity.roles must be a mapping"
            )
        for role_name, role_config in roles.items():
            if not isinstance(role_config, dict):
                raise PolicyValidationError(
                    f"identity.roles.{role_name} must be a mapping"
                )
            self._validate_role_overrides(role_name, role_config)

    def _validate_role_overrides(self, role_name: str, role_config: dict):
        """Validate a single role's override configuration."""
        valid_override_keys = {
            "rate_limits", "actions", "envelope",
        }
        for key in role_config:
            if key not in valid_override_keys:
                raise PolicyValidationError(
                    f"identity.roles.{role_name}.{key} is not a "
                    f"valid override key.  "
                    f"Valid: {valid_override_keys}"
                )

        # Validate rate_limits overrides (same shape as top-level)
        if "rate_limits" in role_config:
            rl = role_config["rate_limits"]
            if not isinstance(rl, dict):
                raise PolicyValidationError(
                    f"identity.roles.{role_name}.rate_limits "
                    f"must be a mapping"
                )
            # Validate global override if present
            if "global" in rl:
                g = rl["global"]
                if "max_calls" in g:
                    if not isinstance(g["max_calls"], int) or g["max_calls"] < 0:
                        raise PolicyValidationError(
                            f"identity.roles.{role_name}."
                            f"rate_limits.global.max_calls "
                            f"must be a non-negative integer"
                        )

        # Validate actions overrides
        if "actions" in role_config:
            acts = role_config["actions"]
            if not isinstance(acts, dict):
                raise PolicyValidationError(
                    f"identity.roles.{role_name}.actions "
                    f"must be a mapping"
                )
            valid_behaviors = {"allow", "deny", "escalate"}
            for tier_name, tier_cfg in acts.items():
                if isinstance(tier_cfg, dict):
                    behavior = tier_cfg.get("behavior")
                    if behavior and behavior not in valid_behaviors:
                        raise PolicyValidationError(
                            f"identity.roles.{role_name}.actions."
                            f"{tier_name}.behavior must be one of "
                            f"{valid_behaviors}"
                        )

        # Validate envelope overrides
        if "envelope" in role_config:
            env = role_config["envelope"]
            if not isinstance(env, dict):
                raise PolicyValidationError(
                    f"identity.roles.{role_name}.envelope "
                    f"must be a mapping"
                )

    def get_role_overrides(self, role: str) -> Optional[dict]:
        """
        Return the override config for a given role, or None.

        The override dict may contain:
          - rate_limits: merged with base rate_limits
          - actions: tier behavior overrides
          - envelope: denied_paths_append list
        """
        return self.identity_roles.get(role)
```

### `default.yaml` — No changes required

The default policy does NOT include an identity section.  This is intentional — it demonstrates backward compatibility.  A separate test fixture YAML will include identity configuration.

### Test Fixture: `test_fixtures/policy_with_identity.yaml`

Create this file for testing:

```yaml
gate:
  name: "identity-test"
  description: "Test policy with identity section"

envelope:
  allowed_paths:
    - "${WORKDIR}/**"
  denied_paths:
    - "${HOME}/.ssh/**"
    - "/tmp/.agent-gate-vault/**"

vault:
  path: "/tmp/.agent-gate-vault"
  retention:
    max_snapshots_per_file: 5
    max_age_days: 7
  naming: "{original_path_hash}/{timestamp}_{filename}"
  on_failure: "deny"

actions:
  destructive:
    patterns:
      - command: "rm"
        description: "File deletion"
  read_only:
    patterns:
      - command: "cat"
      - command: "ls"
  blocked:
    patterns:
      - command: "rm"
        args_contain: ["-rf /"]
        description: "Recursive force delete at root"
  network:
    patterns:
      - command: "curl"
        description: "HTTP client"

gate_behavior:
  on_network:
    default: "escalate"
  on_unclassified:
    default: "deny"

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

logging:
  path: "/tmp/agent-gate-test-logs"
  format: "jsonl"
  log_allowed: true
  log_denied: true
```

---

## Test Cases

### File: `test_policy_loader_identity.py` (NEW)

```
# --- Backward Compatibility ---

test_no_identity_section_loads_normally
    Load default.yaml (no identity section)
    → policy.identity_config == {}
    → policy.identity_roles == {}
    → All existing behavior unchanged

test_no_identity_section_policy_hash_unchanged
    Load default.yaml, check policy_hash matches v0.2.0

# --- Parsing ---

test_identity_section_parsed
    Load policy_with_identity.yaml
    → policy.identity_source == "environment"
    → policy.identity_fields has operator, agent_id, etc.
    → policy.identity_roles has "admin" and "restricted"

test_identity_fields_env_vars_resolved
    Set AGENT_GATE_OPERATOR="sean"
    Load policy_with_identity.yaml
    → policy.identity_fields["operator"] == "sean"

test_identity_roles_parsed
    Load policy_with_identity.yaml
    → policy.identity_roles["admin"]["actions"]["network"]["behavior"] == "allow"
    → policy.identity_roles["restricted"]["rate_limits"]["global"]["max_calls"] == 50

test_get_role_overrides_found
    Load policy_with_identity.yaml
    → policy.get_role_overrides("admin") is not None
    → policy.get_role_overrides("admin")["actions"]["network"]["behavior"] == "allow"

test_get_role_overrides_not_found
    Load policy_with_identity.yaml
    → policy.get_role_overrides("unknown_role") is None

# --- Validation ---

test_invalid_source_raises
    identity.source = "invalid"
    → PolicyValidationError

test_invalid_fields_not_mapping_raises
    identity.fields = "not_a_dict"
    → PolicyValidationError

test_unknown_field_name_raises
    identity.fields.unknown_field = "value"
    → PolicyValidationError

test_invalid_role_not_mapping_raises
    identity.roles.admin = "not_a_dict"
    → PolicyValidationError

test_invalid_role_override_key_raises
    identity.roles.admin.unknown_key = {}
    → PolicyValidationError

test_invalid_role_rate_limit_max_calls_raises
    identity.roles.admin.rate_limits.global.max_calls = -1
    → PolicyValidationError

test_invalid_role_behavior_raises
    identity.roles.admin.actions.network.behavior = "invalid"
    → PolicyValidationError

test_roles_empty_dict_valid
    identity.roles = {}
    → No error (empty roles is fine)

test_fields_empty_dict_valid
    identity.fields = {}
    → No error (empty fields is fine)

# --- Envelope Overrides ---

test_role_envelope_denied_paths_append_parsed
    Load policy_with_identity.yaml
    → policy.identity_roles["restricted"]["envelope"]["denied_paths_append"]
       contains "${WORKDIR}/config/**"

# --- Rate Limit Overrides ---

test_role_rate_limit_global_override_parsed
    Load policy_with_identity.yaml
    → policy.identity_roles["admin"]["rate_limits"]["global"]["max_calls"] == 500

test_role_rate_limit_tools_override_parsed
    Add tools override to fixture, verify parsed correctly

# --- Edge Cases ---

test_identity_section_empty_dict_valid
    identity: {}
    → No error, defaults to source="environment"

test_identity_source_defaults_to_environment
    identity: { fields: { operator: "sean" } }
    → policy.identity_source == "environment"
```

---

## Verification

```bash
# Run new tests only
python -m pytest test_policy_loader_identity.py -v

# Run ALL tests (existing + new)
python -m pytest -x -q

# Expected: 220+ existing pass, ~20 new pass
```

---

## Commit

```
Phase 6.2: Policy loader identity section

- Parse optional identity section from YAML
- Validate source, fields, roles, and role overrides
- Support rate_limits, actions, and envelope overrides per role
- get_role_overrides() method for gate to query role config
- Test fixture: policy_with_identity.yaml
- 20 new tests in test_policy_loader_identity.py
- All existing tests pass (backward compatible)
```
