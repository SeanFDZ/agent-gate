# Phase 7.4: Gate — Verdict.MODIFY, _handle_modify(), Vault Skip

**File:** `agent_gate/gate.py` (MODIFY)
**Depends on:** Phase 7.3 (classifier must provide modification_rules), Phase 7.5 (audit fields must exist)
**Blocked by:** 7.3, 7.5

---

## Before You Start

Read these files to understand the current structure:

- `agent_gate/gate.py` — `Verdict` enum, `GateDecision` dataclass, `evaluate()`, `_handle_destructive()`, `_log_decision()`
- `agent_gate/modifier.py` — `apply_modifications()`, `ModificationError` (from Phase 7.1)
- `agent_gate/classifier_base.py` — `ClassificationResult.modification_rules` (from Phase 7.3)
- `agent_gate/audit.py` — New MODIFY fields on `AuditRecord` (from Phase 7.5)
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Sections 3.1, 3.2, 3.5

---

## Context

The gate is the decision engine.  Phase 7 adds:

1. **`Verdict.MODIFY`** to the enum.
2. **Two new fields on `GateDecision`**: `modified_tool_call` and `modification_feedback`.
3. **`_handle_modify()`**: Called from `_handle_destructive()` when the matched pattern has a `modify` block.  Uses `modifier.apply_modifications()` to rewrite arguments, builds the modified tool call dict, and returns `Verdict.MODIFY`.
4. **Vault skip**: `_handle_destructive()` checks for `vault: skip` on the matched pattern and skips vault backup when present.
5. **Reinvocation suppression**: `evaluate()` accepts `reinvocation: bool = False`.  When True, `_log_decision()` is suppressed (the proxy owns the audit write for MODIFY flows).
6. **`to_agent_message()` MODIFY branch**: Returns structured feedback about what was modified.
7. **`to_dict()` includes modification data** when present.

The gate does NOT own the reinvocation loop.  It returns `Verdict.MODIFY` with the modified tool call, and the proxy decides what to do next.

---

## Deliverables

### Changes to `agent_gate/gate.py`

**1. Add MODIFY to Verdict enum:**

```python
class Verdict(Enum):
    """The gate's final decision on a tool call."""
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    MODIFY = "modify"
```

**2. Add fields to GateDecision:**

```python
@dataclass
class GateDecision:
    verdict: Verdict
    tool_call: dict
    classification: ClassificationResult
    reason: str
    vault_result: Optional[VaultResult] = None
    timestamp: str = ""
    escalation_hint: str = ""
    denial_feedback: str = ""
    rate_status: Optional[dict] = None
    identity: Optional[dict] = None
    modified_tool_call: Optional[dict] = None
    modification_feedback: Optional[dict] = None
```

**3. Update `to_dict()` to include modification data:**

```python
def to_dict(self) -> dict:
    d = {
        # ... existing fields ...
    }
    if self.rate_status:
        d["rate_status"] = self.rate_status
    if self.identity:
        d["identity"] = self.identity
    if self.modified_tool_call:
        d["modified_tool_call"] = self.modified_tool_call
    if self.modification_feedback:
        d["modification_feedback"] = self.modification_feedback
    return d
```

**4. Add MODIFY branch to `to_agent_message()`:**

```python
def to_agent_message(self) -> str:
    if self.verdict == Verdict.ALLOW:
        return ""

    if self.verdict == Verdict.MODIFY:
        lines = ["ACTION MODIFIED:"]
        if self.modification_feedback:
            fb = self.modification_feedback
            lines.append(f"REASON: {fb.get('reason', self.reason)}")
            if "original_call" in fb:
                lines.append(f"ORIGINAL: {fb['original_call']}")
            if "modified_call" in fb:
                lines.append(f"MODIFIED: {fb['modified_call']}")
            if "policy_rule" in fb:
                lines.append(f"POLICY RULE: {fb['policy_rule']}")
        else:
            lines.append(f"REASON: {self.reason}")
        return "\n".join(lines)

    # ... existing DENY/ESCALATE logic unchanged ...
```

**5. Add `reinvocation` parameter to `evaluate()`:**

```python
def evaluate(self, tool_call: dict, reinvocation: bool = False) -> GateDecision:
    # ... existing steps 0-6 unchanged ...

    # Step 7: Attach identity
    decision.identity = (
        self.identity.to_dict() if self.identity else None
    )

    # Step 8: Record outcome for circuit breaker
    success = decision.verdict in (Verdict.ALLOW, Verdict.MODIFY)
    self.rate_tracker.record_outcome(tool_name, success, 0)

    # Step 9: Log the decision (suppressed on reinvocation)
    if not reinvocation:
        self._log_decision(decision)

    return decision
```

**6. Add `_handle_modify()` method:**

```python
def _handle_modify(
    self, tool_call: dict, classification: ClassificationResult
) -> GateDecision:
    """
    Apply modify operations and return Verdict.MODIFY.

    Called from _handle_destructive() when the matched pattern
    has a modify block.  Uses modifier.apply_modifications() to
    rewrite arguments, then builds the modified tool call dict.

    On ModificationError, returns Verdict.DENY (fail closed).
    """
    from agent_gate.modifier import apply_modifications, ModificationError

    modify_block = classification.modification_rules
    try:
        modified_args, ops_applied = apply_modifications(
            classification.command,
            classification.args,
            modify_block,
        )
    except ModificationError as e:
        return GateDecision(
            verdict=Verdict.DENY,
            tool_call=tool_call,
            classification=classification,
            reason=f"Modification failed: {e}.  Action denied.",
            denial_feedback=str(e),
            escalation_hint=(
                "Fix the modify rule in the policy, or "
                "submit a corrected command."
            ),
        )

    # Build modified tool call dict
    modified_tool_call = dict(tool_call)
    modified_input = dict(tool_call.get("input", {}))

    if tool_call.get("tool") == "bash":
        # Reconstruct the command string
        modified_cmd = classification.command
        if modified_args:
            modified_cmd += " " + " ".join(modified_args)
        modified_input["command"] = modified_cmd
    modified_tool_call["input"] = modified_input

    # Build structured feedback
    description = classification.matched_pattern.get("description", "")
    rule_id = f"{classification.command}-modify"
    modification_feedback = {
        "verdict": "MODIFY",
        "original_call": {
            "tool": tool_call.get("tool", ""),
            "args": f"{classification.command} {' '.join(classification.args)}",
        },
        "modified_call": {
            "tool": modified_tool_call.get("tool", ""),
            "args": modified_input.get("command", ""),
        },
        "reason": f"{description}" if description else "Policy modification applied.",
        "policy_rule": rule_id,
        "operations_applied": ops_applied,
    }

    return GateDecision(
        verdict=Verdict.MODIFY,
        tool_call=tool_call,
        classification=classification,
        reason=f"Action modified: {description}",
        modified_tool_call=modified_tool_call,
        modification_feedback=modification_feedback,
    )
```

**7. Update `_handle_destructive()` for vault skip and modify delegation:**

```python
def _handle_destructive(
    self, tool_call: dict, classification: ClassificationResult
) -> GateDecision:
    """
    Destructive action — check for modify rules first, then
    vault skip, then existing vault backup logic.
    """
    # Check conditions before anything else
    if not self._evaluate_conditions(classification):
        condition = classification.matched_pattern.get("condition", "")
        return GateDecision(
            verdict=Verdict.ALLOW,
            tool_call=tool_call,
            classification=classification,
            reason=(
                f"Condition '{condition}' not met.  "
                f"Action allowed without vault backup."
            ),
        )

    # Check for modify rules — delegate to _handle_modify()
    if classification.modification_rules:
        return self._handle_modify(tool_call, classification)

    # Check for vault: skip
    pattern = classification.matched_pattern or {}
    vault_override = pattern.get("vault")

    if vault_override == "skip":
        # Audit the action but skip vault backup
        return GateDecision(
            verdict=Verdict.ALLOW,
            tool_call=tool_call,
            classification=classification,
            reason=(
                f"Destructive action allowed (vault: skip).  "
                f"Audit record written, no vault backup."
            ),
        )

    # Existing vault backup logic (unchanged) ...
    action_desc = (
        f"{classification.command} {' '.join(classification.args)}"
    )
    # ... rest of existing vault logic ...
```

**Important:** The `import` for modifier is done inside `_handle_modify()` to avoid circular imports and to keep modifier as a lazy dependency.

---

## Test Cases

### File: `tests/test_gate_modify.py` (NEW)

```
test_verdict_modify_in_enum
    Verdict.MODIFY.value == "modify"

test_gate_decision_has_modify_fields
    GateDecision(..., modified_tool_call={...}, modification_feedback={...})
    -> fields are accessible

test_to_dict_includes_modify_data
    decision = GateDecision(verdict=Verdict.MODIFY, ..., modified_tool_call={...})
    d = decision.to_dict()
    -> "modified_tool_call" in d

test_to_dict_omits_modify_when_none
    decision = GateDecision(verdict=Verdict.ALLOW, ...)
    d = decision.to_dict()
    -> "modified_tool_call" not in d

test_to_agent_message_modify
    decision = GateDecision(verdict=Verdict.MODIFY, ...,
        modification_feedback={"reason": "Clamped", "policy_rule": "chmod-clamp"})
    msg = decision.to_agent_message()
    -> contains "ACTION MODIFIED"

test_to_agent_message_allow_unchanged
    decision = GateDecision(verdict=Verdict.ALLOW, ...)
    -> to_agent_message() == ""

test_handle_modify_returns_modify_verdict
    Gate with policy containing chmod modify: {clamp_permission: "755"}
    evaluate(chmod 777 deploy.sh)
    -> verdict == Verdict.MODIFY

test_handle_modify_returns_modified_tool_call
    Gate with chmod clamp policy
    decision = evaluate(chmod 777 deploy.sh)
    -> decision.modified_tool_call["input"]["command"] == "chmod 755 deploy.sh"

test_handle_modify_returns_feedback
    Gate with chmod clamp policy
    decision = evaluate(chmod 777 deploy.sh)
    -> decision.modification_feedback is not None
    -> "operations_applied" in decision.modification_feedback

test_handle_modify_fail_closed
    Gate with modify that will error (e.g., clamp_permission: "999")
    evaluate(chmod 777 deploy.sh)
    -> verdict == Verdict.DENY

test_vault_skip_allows_without_backup
    Gate with pattern: {command: "chmod", vault: skip}
    evaluate(chmod 644 file.txt)
    -> verdict == Verdict.ALLOW, vault_result is None

test_vault_skip_with_modify
    Gate with pattern: {command: "chmod", vault: skip, modify: {clamp_permission: "755"}}
    evaluate(chmod 777 file.txt)
    -> verdict == Verdict.MODIFY (modify takes precedence)

test_reinvocation_suppresses_log
    Gate with any tool call
    evaluate(tool_call, reinvocation=True)
    -> _log_decision not called (mock to verify)

test_reinvocation_false_default
    evaluate(tool_call) without reinvocation param
    -> _log_decision IS called

test_modify_success_counted_as_success
    evaluate returns Verdict.MODIFY
    -> rate_tracker.record_outcome called with success=True

test_destructive_without_modify_unchanged
    Gate with standard rm pattern (no modify block)
    evaluate(rm file.txt)
    -> verdict == Verdict.ALLOW (with vault backup, existing behavior)

test_condition_not_met_bypasses_modify
    Gate with pattern: {command: "write_file", condition: "target_exists", modify: ...}
    Target does not exist
    -> verdict == Verdict.ALLOW (condition not met, no modify)

test_modify_preserves_original_tool_call
    decision = evaluate(chmod 777 deploy.sh)
    -> decision.tool_call is the original (unchanged)

test_modify_with_strip_flags
    Gate with rm modify: {strip_flags: ["-f"]}
    evaluate(rm -f file.txt)
    -> modified_tool_call command is "rm file.txt"

test_allowed_property_false_for_modify
    decision with Verdict.MODIFY
    -> decision.allowed is False (not ALLOW)
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_gate_modify.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all existing tests pass, ~20 new tests pass
```

---

## Commit

```
Phase 7.4: Gate Verdict.MODIFY, vault skip, reinvocation

Modified: agent_gate/gate.py
- Verdict.MODIFY added to enum
- GateDecision gains modified_tool_call, modification_feedback
- to_dict() includes modification data when present
- to_agent_message() gains MODIFY branch
- evaluate() accepts reinvocation parameter, suppresses audit
- _handle_modify() delegates to modifier.apply_modifications()
- _handle_destructive() checks modify block, vault: skip
- MODIFY counted as success for circuit breaker
- ~20 new tests in tests/test_gate_modify.py
```
