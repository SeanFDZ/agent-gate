# Phase 6.5: OPA Classifier & yaml_to_rego — Identity in Policy Engine

**Files:** `opa_classifier.py`, `yaml_to_rego.py`
**Depends on:** Phase 6.1 (identity.py), Phase 6.2 (policy_loader.py)
**Parallel with:** Phase 6.3 (gate.py), Phase 6.4 (audit.py)

---

## Before You Start

```bash
cat opa_classifier.py    # Current OPA input document construction
cat yaml_to_rego.py      # Current Rego generation (full file)
cat agent_gate.rego       # Current generated Rego policy
cat agent_gate_test.rego  # Current generated Rego tests
cat identity.py          # Phase 6.1 output
cat policy_loader.py     # Phase 6.2 output (identity_roles)
```

---

## Context

Two changes in this phase:

1. **OPA Classifier:** Include `input.identity` in the OPA input document so Rego policies can make identity-aware decisions.
2. **yaml_to_rego:** Generate RBAC-aware Rego rules from the `identity.roles` section of YAML policy, and generate corresponding test scaffolds.

The OPA input document currently has `command`, `args`, `target_paths`, `tool`, `raw_input`, `envelope`, and optionally `rate_context`.  We add `identity` as another optional field.

---

## Deliverables

### `opa_classifier.py` Changes

```python
class OPAClassifier(ClassifierBase):

    def __init__(self, policy, opa_config=None, identity=None):
        super().__init__(policy)
        self.identity = identity  # Optional IdentityContext
        # ... existing init ...

    def _build_input(
        self,
        command: str,
        args: List[str],
        target_paths: List[str],
        tool_call: dict,
    ) -> dict:
        """
        Build the OPA input document.

        Now includes identity context if available.
        """
        doc = {
            "command": command,
            "args": args,
            "target_paths": target_paths,
            "tool": tool_call.get("tool", ""),
            "raw_input": tool_call.get("input", {}),
            "envelope": {
                "allowed_paths": self.policy.allowed_paths,
                "denied_paths": self.policy.denied_paths,
            },
        }

        # Add identity if available
        if self.identity and self.identity.has_identity():
            doc["identity"] = self.identity.to_dict()

        return doc
```

Also update `Gate._create_classifier()` to pass identity to OPAClassifier:

```python
# In gate.py _create_classifier():
elif effective_backend == "opa":
    from agent_gate.opa_classifier import OPAClassifier
    config = opa_config or raw.get("classifier", {}).get("opa", {})
    return OPAClassifier(
        self.policy,
        opa_config=config,
        identity=self.identity,  # NEW
    )
```

### `yaml_to_rego.py` Changes

Add a new section generator for identity-based role overrides:

```python
def generate_identity_data(policy: dict) -> str:
    """Generate Rego data objects from the identity.roles section.

    Emits role definitions with their override configurations
    so Rego policies can differentiate by input.identity.role.
    """
    identity = policy.get("identity", {})
    roles = identity.get("roles", {})

    if not roles:
        return "# No identity roles defined\nidentity_roles := {}"

    lines = []
    lines.append("# Identity role definitions")
    lines.append("identity_roles := {")
    for role_name, role_config in roles.items():
        lines.append(f'    "{_escape_rego(role_name)}": {{')

        # Actions overrides
        actions = role_config.get("actions", {})
        if actions:
            lines.append('        "actions": {')
            for tier, cfg in actions.items():
                behavior = cfg.get("behavior", "")
                lines.append(
                    f'            "{_escape_rego(tier)}": '
                    f'{{"behavior": "{_escape_rego(behavior)}"},'
                )
            lines.append('        },')

        # Rate limit overrides
        rl = role_config.get("rate_limits", {})
        if rl:
            lines.append('        "rate_limits": {')
            for scope, cfg in rl.items():
                max_calls = cfg.get("max_calls", 0)
                window = cfg.get("window_seconds", 60)
                lines.append(
                    f'            "{_escape_rego(scope)}": '
                    f'{{"max_calls": {max_calls}, '
                    f'"window_seconds": {window}}},'
                )
            lines.append('        },')

        lines.append("    },")
    lines.append("}")

    return "\n".join(lines)


def generate_identity_rules() -> str:
    """Generate Rego rules for identity-based policy evaluation.

    These rules check input.identity.role against identity_roles
    data to determine role-specific behavior overrides.
    """
    return '''\
# Identity: check if current role has an override for a tier
role_has_override(tier_name) if {
    input.identity
    input.identity.role
    role_config := identity_roles[input.identity.role]
    role_config.actions[tier_name]
}

# Identity: get the behavior override for a tier
role_behavior(tier_name) := behavior if {
    input.identity
    input.identity.role
    role_config := identity_roles[input.identity.role]
    behavior := role_config.actions[tier_name].behavior
}

# Identity: check if role has rate limit override
role_rate_limit(scope) := config if {
    input.identity
    input.identity.role
    role_config := identity_roles[input.identity.role]
    config := role_config.rate_limits[scope]
}'''
```

Update `generate_rego()` to include identity sections:

```python
def generate_rego(policy: dict, source_file: str = "unknown") -> str:
    # ... existing code ...

    # After gate behavior, before decision rules:
    # Add identity data and rules
    identity_section = generate_identity_data(policy)
    identity_rules = generate_identity_rules()
    parts.append(identity_section)
    parts.append(identity_rules)

    # ... existing decision rules ...
```

Add identity-aware decision rules in the decision chain:

```python
DECISION_RULES_IDENTITY = '''\

# Identity override: role-based network allow
decision := result if {
    all_paths_in_envelope
    not any_rate_limit_active
    some name, pattern in network_result
    role_has_override("network")
    role_behavior("network") == "allow"
    result := {
        "tier": "network",
        "reason": concat("", [
            "Network action allowed for role: ",
            input.identity.role,
        ]),
        "paths_in_envelope": true,
        "paths_outside_envelope": [],
        "matched_pattern": pattern,
    }
}'''
```

Update `generate_test_scaffold()` to include identity tests:

```python
# Add to test scaffold generation:
identity_test_lines = [
    "# =========================================================================",
    "# IDENTITY / RBAC TESTS",
    "# =========================================================================",
    "",
    "# Helper: build input with identity",
    "make_identity_input(cmd, args, paths, role) := {",
    '    "command": cmd,',
    '    "args": args,',
    '    "target_paths": paths,',
    '    "tool": "bash",',
    '    "raw_input": {},',
    '    "envelope": mock_envelope,',
    '    "identity": {"role": role, "operator": "test"},',
    "}",
]

# Add tests for each role with action overrides
for role_name, role_config in roles.items():
    actions = role_config.get("actions", {})
    for tier_name, tier_cfg in actions.items():
        behavior = tier_cfg.get("behavior", "")
        # Generate appropriate test based on behavior
```

---

## Test Cases

### File: `test_opa_identity.py` (NEW)

```
# --- OPA Input Document ---

test_opa_input_no_identity
    OPAClassifier with identity=None
    input_doc = classifier._build_input(...)
    → "identity" not in input_doc

test_opa_input_with_identity
    identity = IdentityContext(operator="sean", role="admin")
    OPAClassifier with identity=identity
    input_doc = classifier._build_input(...)
    → input_doc["identity"]["operator"] == "sean"
    → input_doc["identity"]["role"] == "admin"

test_opa_input_identity_session_only_excluded
    identity = IdentityContext(session_id="abc")
    → "identity" not in input_doc (has_identity() is False)

# --- yaml_to_rego Identity Generation ---

test_generate_identity_data_no_roles
    policy without identity section
    → output contains 'identity_roles := {}'

test_generate_identity_data_with_roles
    policy with admin and restricted roles
    → output contains '"admin"' and '"restricted"'
    → output contains '"behavior": "allow"'

test_generate_identity_rules
    → output contains 'role_has_override'
    → output contains 'role_behavior'

test_generate_rego_includes_identity_section
    Full generate_rego() with identity roles
    → output contains 'identity_roles'
    → output contains 'role_has_override'

test_generate_rego_no_identity_still_works
    Full generate_rego() without identity section
    → output compiles with OPA (empty identity_roles)

# --- Rego Test Scaffold ---

test_scaffold_includes_identity_tests
    generate_test_scaffold() with identity roles
    → output contains 'make_identity_input'
    → output contains test functions for role overrides

# --- Round-trip ---

test_yaml_to_rego_identity_round_trip
    Generate Rego from policy_with_identity.yaml
    Run OPA eval with identity input
    → Admin role gets network allow
    → No identity gets network escalate
```

---

## Verification

```bash
python -m pytest test_opa_identity.py -v

# If OPA is available, run generated Rego tests:
python -m agent_gate.yaml_to_rego test_fixtures/policy_with_identity.yaml \
    -o /tmp/test_identity.rego --tests /tmp/test_identity_test.rego
opa test /tmp/test_identity.rego /tmp/test_identity_test.rego -v

python -m pytest -x -q  # All tests
# Expected: all existing + ~15 new pass
```

---

## Commit

```
Phase 6.5: OPA classifier and yaml_to_rego identity support

- OPAClassifier: input.identity in OPA input document
- yaml_to_rego: generate_identity_data() for role definitions
- yaml_to_rego: generate_identity_rules() for RBAC Rego rules
- yaml_to_rego: identity-aware decision rules (role overrides)
- yaml_to_rego: test scaffold includes RBAC tests
- Gate._create_classifier passes identity to OPAClassifier
- 15 new tests in test_opa_identity.py
- All existing tests pass
```
