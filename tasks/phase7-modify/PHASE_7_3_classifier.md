# Phase 7.3: Classifier — Modification Rules and args_match

**Files:** `agent_gate/classifier_base.py` (MODIFY), `agent_gate/classifier.py` (MODIFY)
**Depends on:** Phase 7.2 (policy_loader must validate new fields first)
**Parallel with:** Phases 7.5, 7.6 (different files, no conflicts)

---

## Before You Start

Read these files to understand the current structure:

- `agent_gate/classifier_base.py` — `ClassificationResult` dataclass, `ClassifierBase` abstract class
- `agent_gate/classifier.py` — `PythonClassifier._match_tier()`, `_index_patterns()`, `_evaluate()`
- `agent_gate/gate.py` — How `ClassificationResult.matched_pattern` is used downstream
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Schema for `args_match` and `modify`

---

## Context

The classifier needs two changes:

1. **`ClassificationResult`** gains a new field `modification_rules: Optional[dict] = None`.  When a matched pattern has a `modify` block, the classifier copies it into this field so the gate can use it downstream.

2. **`PythonClassifier._match_tier()`** gains support for `args_match` regex matching.  This complements the existing `args_contain` substring matching.  Both can appear on the same pattern; if both are present, both must match.

The classifier does NOT apply modifications.  It only reports that modifications are available via `modification_rules`.  The gate delegates actual modification to `modifier.py`.

---

## Deliverables

### Changes to `agent_gate/classifier_base.py`

Add one field to `ClassificationResult`:

```python
@dataclass
class ClassificationResult:
    """
    The output of classifying a tool call.
    Contains everything the gate needs to decide what to do.
    """
    tier: ActionTier
    command: str
    args: List[str]
    target_paths: List[str]
    matched_pattern: Optional[dict] = None
    reason: str = ""
    paths_in_envelope: bool = True
    paths_outside_envelope: List[str] = field(default_factory=list)
    modification_rules: Optional[dict] = None  # Phase 7: modify block from matched pattern
```

### Changes to `agent_gate/classifier.py`

**1. Update `_match_tier()` to support `args_match` and pass `modify` block:**

```python
def _match_tier(
    self,
    command: str,
    args: List[str],
    tier_index: dict,
    tier: ActionTier,
) -> Optional[ClassificationResult]:
    """
    Check if a command matches any pattern in a given tier.
    Returns ClassificationResult if matched, None if not.
    """
    if command not in tier_index:
        return None

    for pattern in tier_index[command]:
        # Check args_contain (existing behavior)
        if "args_contain" in pattern:
            args_str = " ".join(args)
            full_str = f"{command} {args_str}"
            matched = any(
                re.search(re.escape(trigger) + r'(\s|$)', full_str)
                for trigger in pattern["args_contain"]
            )
            if not matched:
                continue

        # Check args_match (new: regex on full argument string)
        if "args_match" in pattern:
            args_str = " ".join(args)
            full_str = f"{command} {args_str}"
            try:
                if not re.search(pattern["args_match"], full_str):
                    continue
            except re.error:
                # Invalid regex should have been caught by policy loader,
                # but fail safely if it wasn't.
                continue

        reason = pattern.get(
            "description", f"Matched {tier.value} pattern"
        )

        # Extract modification_rules if present
        modification_rules = pattern.get("modify")

        return ClassificationResult(
            tier=tier,
            command=command,
            args=args,
            target_paths=[],  # filled by caller
            matched_pattern=pattern,
            reason=reason,
            modification_rules=modification_rules,
        )

    return None
```

---

## Test Cases

### File: `tests/test_classifier_modify.py` (NEW)

```
test_args_match_simple_regex
    Pattern: {command: "database_query", args_match: "^SELECT"}
    Tool call: bash "database_query SELECT * FROM users"
    -> matches, tier=destructive

test_args_match_negative_lookahead
    Pattern: {command: "curl", args_match: "^(?!.*--max-time).*"}
    Tool call: bash "curl http://example.com"
    -> matches (no --max-time present)

test_args_match_negative_lookahead_no_match
    Pattern: {command: "curl", args_match: "^(?!.*--max-time).*"}
    Tool call: bash "curl --max-time 30 http://example.com"
    -> does NOT match

test_args_match_and_args_contain_both_required
    Pattern: {command: "rm", args_contain: ["-f"], args_match: ".*\\.txt$"}
    Tool call: bash "rm -f file.txt"
    -> matches (both conditions met)

test_args_match_and_args_contain_partial_fail
    Pattern: {command: "rm", args_contain: ["-f"], args_match: ".*\\.txt$"}
    Tool call: bash "rm -f file.py"
    -> does NOT match (args_match fails)

test_modify_block_passed_to_classification_result
    Pattern: {command: "chmod", modify: {clamp_permission: "755"}}
    Tool call: bash "chmod 777 deploy.sh"
    -> ClassificationResult.modification_rules == {clamp_permission: "755"}

test_no_modify_block_classification_result_none
    Pattern: {command: "rm"} (no modify key)
    Tool call: bash "rm file.txt"
    -> ClassificationResult.modification_rules is None

test_modify_block_with_multiple_ops
    Pattern: {command: "rm", args_contain: ["-f"], modify: {strip_flags: ["-f"], require_flags: ["--interactive"]}}
    Tool call: bash "rm -f file.txt"
    -> modification_rules == {strip_flags: ["-f"], require_flags: ["--interactive"]}

test_args_match_invalid_regex_skipped
    Pattern: {command: "test", args_match: "[invalid"}
    Tool call: bash "test foo"
    -> pattern does NOT match (invalid regex skipped gracefully)

test_first_match_wins_with_modify
    Two patterns for "chmod": first has modify, second doesn't
    Tool call: bash "chmod 777 file.txt"
    -> first pattern matches, modification_rules from first pattern

test_args_match_on_network_tier
    Pattern in network tier: {command: "curl", args_match: ".*"}
    Tool call: bash "curl http://example.com"
    -> matches, tier=network

test_backward_compat_existing_patterns
    Existing rm, mv, chmod patterns without modify/args_match
    -> all match exactly as before, modification_rules is None

test_classification_result_has_modification_rules_field
    ClassificationResult(tier=..., command=..., args=[], target_paths=[])
    -> modification_rules defaults to None

test_modification_rules_preserved_through_evaluate
    Full classify() call with modify pattern
    -> ClassificationResult.modification_rules is not None

test_args_match_empty_args
    Pattern: {command: "cmd", args_match: "^cmd$"}
    Tool call: bash "cmd" (no args)
    -> matches
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_classifier_modify.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all 313+ existing tests pass, ~15 new tests pass
```

---

## Commit

```
Phase 7.3: Classifier args_match and modification_rules

Modified: agent_gate/classifier_base.py
- ClassificationResult gains modification_rules: Optional[dict]

Modified: agent_gate/classifier.py
- _match_tier() supports args_match regex matching
- _match_tier() passes modify block into modification_rules
- args_match and args_contain can coexist (both must match)
- ~15 new tests in tests/test_classifier_modify.py
```
