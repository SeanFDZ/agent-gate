# Phase 7.2: Policy Loader — Modify Schema Validation

**File:** `agent_gate/policy_loader.py` (MODIFY)
**Depends on:** Phase 7.1 (modifier.py must exist for operation key validation)
**Parallel:** Nothing after this starts until 7.2 passes.

---

## Before You Start

Read these files to understand the current structure:

- `agent_gate/policy_loader.py` — Current validation logic, `_validate()`, `_validate_identity()`, `_validate_role_overrides()`
- `agent_gate/modifier.py` — The OPERATION_HANDLERS registry (from Phase 7.1)
- `policies/default.yaml` — Current policy structure, pattern entries
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Canonical schema for `modify`, `args_match`, `vault` fields

---

## Context

The policy loader must parse and validate three new fields that can appear on pattern entries:

1. **`modify`** (dict): Contains operation keys from the canonical set (`clamp_permission`, `strip_flags`, `require_flags`, `append_arg`, `max_depth`).  Each key must be in the known operations set.  Values are not deeply validated here (the modifier handles that at runtime), but types are checked.

2. **`args_match`** (string): A regex pattern for matching the full argument string.  Must compile without error via `re.compile()`.

3. **`vault`** (string): Pattern-level vault override.  Only `"skip"` is valid in Phase 7.

Additionally, `modify_rules` must be added to `_validate_role_overrides()` as a valid override key (accepted but ignored, schema reservation for future phases).

---

## Deliverables

### Changes to `agent_gate/policy_loader.py`

**1. Add pattern validation method `_validate_pattern()`:**

```python
def _validate_pattern(self, tier_name: str, idx: int, pattern: dict):
    """Validate a single pattern entry within a tier."""
    prefix = f"actions.{tier_name}.patterns[{idx}]"

    # Validate args_match (optional, must be compilable regex)
    if "args_match" in pattern:
        args_match = pattern["args_match"]
        if not isinstance(args_match, str):
            raise PolicyValidationError(
                f"{prefix}.args_match must be a string"
            )
        try:
            re.compile(args_match)
        except re.error as e:
            raise PolicyValidationError(
                f"{prefix}.args_match is not a valid regex: {e}"
            )

    # Validate vault (optional, only "skip" in Phase 7)
    if "vault" in pattern:
        vault_val = pattern["vault"]
        valid_vault_values = {"skip"}
        if vault_val not in valid_vault_values:
            raise PolicyValidationError(
                f"{prefix}.vault must be one of "
                f"{valid_vault_values}, got '{vault_val}'"
            )

    # Validate modify (optional, dict of known operations)
    if "modify" in pattern:
        modify = pattern["modify"]
        if not isinstance(modify, dict):
            raise PolicyValidationError(
                f"{prefix}.modify must be a mapping"
            )
        if not modify:
            raise PolicyValidationError(
                f"{prefix}.modify must not be empty"
            )
        known_ops = {
            "clamp_permission", "strip_flags",
            "require_flags", "append_arg", "max_depth",
        }
        for op_name, op_value in modify.items():
            if op_name not in known_ops:
                raise PolicyValidationError(
                    f"{prefix}.modify.{op_name} is not a "
                    f"known operation.  Valid: {known_ops}"
                )
            # Type checks per operation
            if op_name == "clamp_permission":
                if not isinstance(op_value, str):
                    raise PolicyValidationError(
                        f"{prefix}.modify.clamp_permission "
                        f"must be a string"
                    )
            elif op_name in ("strip_flags", "require_flags"):
                if not isinstance(op_value, list):
                    raise PolicyValidationError(
                        f"{prefix}.modify.{op_name} "
                        f"must be a list"
                    )
            elif op_name == "append_arg":
                if not isinstance(op_value, str):
                    raise PolicyValidationError(
                        f"{prefix}.modify.append_arg "
                        f"must be a string"
                    )
            elif op_name == "max_depth":
                if not isinstance(op_value, int):
                    raise PolicyValidationError(
                        f"{prefix}.modify.max_depth "
                        f"must be an integer"
                    )
```

**2. Call `_validate_pattern()` from `_validate()`:**

In the existing loop that checks action tiers have patterns, add pattern-level validation:

```python
# After the existing tier/patterns check in _validate():
for tier in self.REQUIRED_ACTION_TIERS:
    # ... existing checks ...
    # Add pattern-level validation
    for idx, pattern in enumerate(actions[tier]["patterns"]):
        self._validate_pattern(tier, idx, pattern)

# Also validate optional network tier patterns
if "network" in actions:
    for idx, pattern in enumerate(actions["network"].get("patterns", [])):
        self._validate_pattern("network", idx, pattern)
```

**3. Add `modify_rules` to valid role override keys:**

```python
def _validate_role_overrides(self, role_name: str, role_config: dict):
    """Validate a single role's override configuration."""
    valid_override_keys = {
        "rate_limits", "actions", "envelope", "modify_rules",
    }
    # ... rest unchanged ...
```

---

## Test Cases

### File: `tests/test_policy_loader_modify.py` (NEW)

```
test_valid_modify_block_accepted
    Policy with pattern containing modify: {clamp_permission: "755"}
    -> loads without error

test_valid_args_match_accepted
    Policy with pattern containing args_match: "^SELECT"
    -> loads without error

test_valid_vault_skip_accepted
    Policy with pattern containing vault: skip
    -> loads without error

test_invalid_args_match_bad_regex
    Policy with args_match: "[invalid"
    -> raises PolicyValidationError mentioning "not a valid regex"

test_invalid_vault_unknown_value
    Policy with vault: "archive"
    -> raises PolicyValidationError mentioning valid values

test_invalid_vault_boolean
    Policy with vault: true
    -> raises PolicyValidationError (must be string)

test_invalid_modify_not_dict
    Policy with modify: "clamp"
    -> raises PolicyValidationError "must be a mapping"

test_invalid_modify_empty
    Policy with modify: {}
    -> raises PolicyValidationError "must not be empty"

test_invalid_modify_unknown_operation
    Policy with modify: {unknown_op: "value"}
    -> raises PolicyValidationError mentioning "known operation"

test_invalid_clamp_permission_not_string
    Policy with modify: {clamp_permission: 755}
    -> raises PolicyValidationError "must be a string"

test_invalid_strip_flags_not_list
    Policy with modify: {strip_flags: "-f"}
    -> raises PolicyValidationError "must be a list"

test_invalid_max_depth_not_int
    Policy with modify: {max_depth: "2"}
    -> raises PolicyValidationError "must be an integer"

test_modify_rules_accepted_in_role
    Policy with identity.roles.dev.modify_rules: [...]
    -> loads without error (accepted, ignored)

test_backward_compat_no_modify_fields
    Existing default.yaml (no modify/args_match/vault keys)
    -> loads without error, all existing tests pass

test_multiple_ops_in_modify_block
    Policy with modify: {strip_flags: ["-f"], require_flags: ["--interactive"]}
    -> loads without error
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_policy_loader_modify.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all 313+ existing tests pass, ~15 new tests pass
```

---

## Commit

```
Phase 7.2: Policy loader modify schema validation

Modified: agent_gate/policy_loader.py
- _validate_pattern() validates modify, args_match, vault on patterns
- Pattern validation called for all tiers during policy load
- modify_rules added to valid role override keys (schema reservation)
- Type checking for all five modify operation values
- ~15 new tests in tests/test_policy_loader_modify.py
```
