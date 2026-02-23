# Phase 7.6: OPA Classifier and yaml_to_rego — Modifications Rule

**Files:** `agent_gate/opa_classifier.py` (MODIFY), `agent_gate/yaml_to_rego.py` (MODIFY)
**Depends on:** Phase 7.2 (policy loader must validate modify blocks)
**Parallel with:** Phases 7.3, 7.5 (different files, no conflicts)

---

## Before You Start

Read these files to understand the current structure:

- `agent_gate/yaml_to_rego.py` — `generate_rego()`, `generate_tier_patterns()`, `_format_pattern_entry()`, `TIER_ORDER`
- `agent_gate/opa_classifier.py` — `_eval_subprocess()`, `_map_result()`, `_build_input()`
- `agent_gate/classifier_base.py` — `ClassificationResult` (with new `modification_rules` from Phase 7.3)
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Section 3.4 (OPA Backend MODIFY Pattern)

---

## Context

OPA returns boolean decisions natively.  MODIFY requires returning structured rewrite data alongside the decision.

**Pattern:** A parallel Rego rule `modifications` returns a set of patch objects when the action would otherwise be denied but a safe form exists.  The gate queries both `data.agent_gate.decision` and `data.agent_gate.modifications`.  A non-empty `modifications` set with `allow == false` signals a MODIFY decision.

**yaml_to_rego.py** must be extended to:
1. Include `modify` and `vault` and `args_match` fields in pattern entries
2. Generate `modifications` Rego rules from patterns that have `modify` blocks
3. Include `args_match` in pattern matching rules

**opa_classifier.py** must be extended to:
1. Query both `decision` and `modifications` from OPA
2. Map non-empty `modifications` with denied decision to `ClassificationResult` with `modification_rules`

---

## Deliverables

### Changes to `agent_gate/yaml_to_rego.py`

**1. Update `_format_pattern_entry()` to include new fields:**

```python
def _format_pattern_entry(key: str, pattern: dict) -> str:
    """Format a single pattern as a Rego object entry."""
    fields = []
    fields.append(f'"command": "{_escape_rego(pattern["command"])}"')
    if "args_contain" in pattern:
        args_str = ", ".join(
            f'"{_escape_rego(a)}"' for a in pattern["args_contain"]
        )
        fields.append(f'"args_contain": [{args_str}]')
    if "args_match" in pattern:
        fields.append(f'"args_match": "{_escape_rego(pattern["args_match"])}"')
    if "condition" in pattern:
        fields.append(f'"condition": "{_escape_rego(pattern["condition"])}"')
    if "description" in pattern:
        fields.append(f'"description": "{_escape_rego(pattern["description"])}"')
    if "vault" in pattern:
        fields.append(f'"vault": "{_escape_rego(pattern["vault"])}"')
    if "modify" in pattern:
        # Encode modify block as JSON-like Rego object
        modify_fields = []
        for op_name, op_value in pattern["modify"].items():
            if isinstance(op_value, list):
                items = ", ".join(f'"{_escape_rego(v)}"' for v in op_value)
                modify_fields.append(f'"{op_name}": [{items}]')
            elif isinstance(op_value, int):
                modify_fields.append(f'"{op_name}": {op_value}')
            else:
                modify_fields.append(f'"{op_name}": "{_escape_rego(str(op_value))}"')
        fields.append('"modify": {' + ", ".join(modify_fields) + '}')

    # Use multi-line for complex patterns
    if len(fields) > 3:
        lines = [f'    "{_escape_rego(key)}": {{']
        for field in fields:
            lines.append(f"        {field},")
        lines.append("    },")
        return "\n".join(lines)
    else:
        obj = ", ".join(fields)
        return f'    "{_escape_rego(key)}": {{{obj}}},'
```

**2. Add `generate_modifications_rules()` function:**

```python
def generate_modifications_rules(policy: dict) -> str:
    """Generate Rego modifications rules from patterns with modify blocks.

    Produces a modifications[patch] rule set that returns patch objects
    for patterns that have modify blocks.  The gate queries this alongside
    the main decision rule.
    """
    lines = []
    lines.append("# Modifications: patterns with modify blocks")
    lines.append("# Non-empty modifications + denied decision signals MODIFY")

    actions = policy.get("actions", {})
    has_any = False

    for tier_name in TIER_ORDER:
        if tier_name not in actions:
            continue
        patterns = actions[tier_name].get("patterns", [])
        for pattern in patterns:
            if "modify" not in pattern:
                continue
            has_any = True
            cmd = pattern["command"]
            desc = pattern.get("description", "")

            # Build the condition body
            conditions = [f'    input.command == "{_escape_rego(cmd)}"']
            if "args_contain" in pattern:
                conditions.append("    args_contain_match(pattern.args_contain)")
            if "args_match" in pattern:
                conditions.append(
                    f'    regex.match("{_escape_rego(pattern["args_match"])}", '
                    f'concat(" ", array.concat([input.command], input.args)))'
                )

            # Build the modify block as a Rego object
            modify_parts = []
            for op_name, op_value in pattern["modify"].items():
                if isinstance(op_value, list):
                    items = ", ".join(f'"{_escape_rego(v)}"' for v in op_value)
                    modify_parts.append(f'"{op_name}": [{items}]')
                elif isinstance(op_value, int):
                    modify_parts.append(f'"{op_name}": {op_value}')
                else:
                    modify_parts.append(
                        f'"{op_name}": "{_escape_rego(str(op_value))}"'
                    )

            modify_obj = "{" + ", ".join(modify_parts) + "}"

            lines.append("")
            lines.append(f"modifications[patch] if {{")
            for cond in conditions:
                lines.append(cond)
            lines.append(f'    patch := {{')
            lines.append(f'        "command": "{_escape_rego(cmd)}",')
            lines.append(f'        "description": "{_escape_rego(desc)}",')
            lines.append(f'        "modify": {modify_obj},')
            if "vault" in pattern:
                lines.append(
                    f'        "vault": "{_escape_rego(pattern["vault"])}",')
            lines.append(f'    }}')
            lines.append(f"}}")

    if not has_any:
        lines.append("")
        lines.append("# No modify patterns defined")
        lines.append("modifications := set()")

    return "\n".join(lines)
```

**3. Update `generate_rego()` to include modifications section:**

Add the modifications rules section after the decision rules:

```python
def generate_rego(policy: dict, source_file: str = "policy.yaml") -> str:
    # ... existing sections ...

    # 8. Modifications rules (for MODIFY verdict support)
    sections.append(
        "# =========================================================================\n"
        "# MODIFICATIONS (patterns with modify blocks)\n"
        "# ========================================================================="
    )
    sections.append(generate_modifications_rules(policy))

    return "\n\n".join(sections) + "\n"
```

**4. Update `generate_tier_result_rules()` to handle `args_match`:**

Add an additional rule variant for patterns with `args_match`:

```python
def generate_tier_result_rules(
    tier_name: str, has_args_contain: bool, has_args_match: bool = False
) -> str:
    """Generate the result matching rules for a tier."""
    rules = []

    # Base rule: command match only (no args_contain, no args_match)
    rules.append(
        f"{tier_name}_result[name] := pattern if {{\n"
        f"    some name, pattern in {tier_name}_patterns\n"
        f"    pattern.command == input.command\n"
        f"    not pattern.args_contain\n"
        f"    not pattern.args_match\n"
        f"}}"
    )

    if has_args_contain:
        rules.append(
            f"\n{tier_name}_result[name] := pattern if {{\n"
            f"    some name, pattern in {tier_name}_patterns\n"
            f"    pattern.command == input.command\n"
            f"    pattern.args_contain\n"
            f"    not pattern.args_match\n"
            f"    args_contain_match(pattern.args_contain)\n"
            f"}}"
        )

    if has_args_match:
        rules.append(
            f"\n{tier_name}_result[name] := pattern if {{\n"
            f"    some name, pattern in {tier_name}_patterns\n"
            f"    pattern.command == input.command\n"
            f"    pattern.args_match\n"
            f"    not pattern.args_contain\n"
            f"    regex.match(pattern.args_match, concat(\" \", array.concat([input.command], input.args)))\n"
            f"}}"
        )

    if has_args_contain and has_args_match:
        rules.append(
            f"\n{tier_name}_result[name] := pattern if {{\n"
            f"    some name, pattern in {tier_name}_patterns\n"
            f"    pattern.command == input.command\n"
            f"    pattern.args_contain\n"
            f"    pattern.args_match\n"
            f"    args_contain_match(pattern.args_contain)\n"
            f"    regex.match(pattern.args_match, concat(\" \", array.concat([input.command], input.args)))\n"
            f"}}"
        )

    return "\n".join(rules)
```

### Changes to `agent_gate/opa_classifier.py`

**1. Update `_eval_subprocess()` to query both decision and modifications:**

```python
def _eval_subprocess(self, input_doc: dict) -> dict:
    # ... existing code to build cmd ...
    # Query both decision and modifications
    query = f"x := {{{{'decision': data.{self.package}.decision, 'modifications': data.{self.package}.modifications}}}}"

    # ... run subprocess ...
    # ... extract result ...

    # Return combined result
    return {
        "decision": ...,  # existing decision object
        "modifications": ...,  # set of patch objects (may be empty)
    }
```

**2. Update `_map_result()` to handle modifications:**

```python
def _map_result(
    self,
    opa_result: dict,
    command: str,
    args: List[str],
    target_paths: List[str],
) -> ClassificationResult:
    # If opa_result has nested structure (decision + modifications)
    if "decision" in opa_result and "modifications" in opa_result:
        decision = opa_result["decision"]
        modifications = opa_result.get("modifications", [])
    else:
        decision = opa_result
        modifications = []

    tier_str = decision.get("tier", "unclassified")
    tier = self.TIER_MAP.get(tier_str, ActionTier.UNCLASSIFIED)

    # ... existing envelope and reason logic ...

    # Check for modifications
    modification_rules = None
    if modifications and isinstance(modifications, (list, set)):
        # Take the first modification (first match wins)
        mod_list = list(modifications)
        if mod_list:
            first_mod = mod_list[0]
            modification_rules = first_mod.get("modify")

    return ClassificationResult(
        tier=tier,
        command=command,
        args=args,
        target_paths=target_paths,
        matched_pattern=matched_pattern,
        reason=reason,
        paths_in_envelope=paths_in_envelope,
        paths_outside_envelope=paths_outside,
        modification_rules=modification_rules,
    )
```

---

## Test Cases

### File: `tests/test_opa_modify.py` (NEW)

```
test_generate_modifications_rules_with_modify
    Policy with chmod pattern having modify: {clamp_permission: "755"}
    rego = generate_modifications_rules(policy)
    -> contains "modifications[patch]"
    -> contains "clamp_permission"

test_generate_modifications_rules_no_modify
    Policy with no modify blocks on any pattern
    rego = generate_modifications_rules(policy)
    -> contains "modifications := set()"

test_format_pattern_entry_with_modify
    Pattern with modify: {strip_flags: ["-f"]}
    entry = _format_pattern_entry("rm_f", pattern)
    -> contains '"modify"' and '"strip_flags"'

test_format_pattern_entry_with_vault
    Pattern with vault: "skip"
    entry = _format_pattern_entry("chmod", pattern)
    -> contains '"vault": "skip"'

test_format_pattern_entry_with_args_match
    Pattern with args_match: "^SELECT"
    entry = _format_pattern_entry("query", pattern)
    -> contains '"args_match"'

test_generate_rego_includes_modifications_section
    rego = generate_rego(policy_with_modify)
    -> contains "MODIFICATIONS"

test_generate_rego_backward_compat
    rego = generate_rego(existing_default_policy)
    -> still generates valid Rego (no errors)

test_tier_result_rules_with_args_match
    rules = generate_tier_result_rules("destructive", False, True)
    -> contains "regex.match"

test_modifications_rule_includes_vault
    Policy with chmod: vault: skip, modify: {clamp_permission: "755"}
    rego = generate_modifications_rules(policy)
    -> patch object includes "vault": "skip"

test_map_result_with_modifications
    opa_result = {"decision": {"tier": "destructive"}, "modifications": [{"modify": {"clamp_permission": "755"}}]}
    result = _map_result(opa_result, "chmod", ["777", "f"], ["/f"])
    -> result.modification_rules == {"clamp_permission": "755"}

test_map_result_without_modifications
    opa_result = {"decision": {"tier": "destructive"}, "modifications": []}
    result = _map_result(opa_result, "rm", ["-f"], ["/f"])
    -> result.modification_rules is None

test_map_result_legacy_format
    opa_result = {"tier": "destructive", "reason": "file deletion"}
    result = _map_result(opa_result, "rm", [], [])
    -> works (backward compatible)

test_generate_pattern_key_with_args_match
    Pattern with args_match and no args_contain
    key = generate_pattern_key("curl", pattern, set())
    -> includes "curl" (not duplicated)

test_generate_rego_full_roundtrip
    Policy with modify, vault, args_match patterns
    rego = generate_rego(policy)
    -> rego string is non-empty, contains all sections

test_modifications_multiple_patterns
    Policy with two modify patterns (chmod and rm)
    rego = generate_modifications_rules(policy)
    -> contains two "modifications[patch]" blocks
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_opa_modify.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Optionally: generate Rego from a test policy and inspect
python -m agent_gate.yaml_to_rego policies/default.yaml

# Expected: all existing tests pass, ~15 new tests pass
```

---

## Commit

```
Phase 7.6: OPA and yaml_to_rego modifications support

Modified: agent_gate/yaml_to_rego.py
- _format_pattern_entry() includes modify, vault, args_match fields
- generate_modifications_rules() compiles modify blocks to Rego
- generate_rego() includes modifications section
- Tier result rules support args_match regex matching

Modified: agent_gate/opa_classifier.py
- Queries both decision and modifications from OPA
- Maps non-empty modifications to ClassificationResult.modification_rules
- Backward compatible with existing decision-only responses
- ~15 new tests in tests/test_opa_modify.py
```
