# Phase 7.5: Audit Logger — MODIFY Record Fields

**File:** `agent_gate/audit.py` (MODIFY)
**Depends on:** Phase 7.2 (policy loader must validate new fields)
**Parallel with:** Phases 7.3, 7.6 (different files, no conflicts)

---

## Before You Start

Read these files to understand the current structure:

- `agent_gate/audit.py` — `AuditRecord` dataclass, `AuditLogger.log_tool_call()`, `_content_for_hashing()`, `_chain_record()`
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Section 3.3 (Audit Record for MODIFY)

---

## Context

The audit record needs four new Optional fields to capture MODIFY decisions.  These fields are populated by the proxy (which owns the MODIFY audit write), not by the gate.

The existing hash chaining mechanism requires NO changes.  `_content_for_hashing()` already uses `asdict()` with `sort_keys=True` and filters out None values.  New Optional fields are automatically included in the hash when non-None.

The existing `arguments` field always means "what the agent submitted" (original parameters).  The new `modified_tool_call` field carries the rewritten parameters.

---

## Deliverables

### Changes to `agent_gate/audit.py`

**1. Add four new fields to `AuditRecord`:**

```python
@dataclass
class AuditRecord:
    timestamp: str
    tool_name: str
    arguments: dict
    verdict: str
    tier: str
    reason: str
    server_name: Optional[str] = None
    session_id: Optional[str] = None
    msg_id: Optional[Any] = None
    vault_path: Optional[str] = None
    duration_ms: Optional[float] = None
    policy_hash: Optional[str] = None
    rate_context: Optional[dict] = None
    prev_hash: Optional[str] = None
    record_hash: Optional[str] = None
    # Identity fields (Phase 6.4)
    operator: Optional[str] = None
    agent_id: Optional[str] = None
    service_account: Optional[str] = None
    role: Optional[str] = None
    # MODIFY fields (Phase 7.5)
    original_tool_call: Optional[dict] = None
    modified_tool_call: Optional[dict] = None
    modification_rule: Optional[dict] = None
    reinvocation_verdict: Optional[str] = None
```

**2. Add parameters to `log_tool_call()`:**

```python
def log_tool_call(
    self,
    tool_name: str,
    arguments: dict,
    verdict: str,
    tier: str,
    reason: str,
    msg_id: Optional[Any] = None,
    vault_path: Optional[str] = None,
    duration_ms: Optional[float] = None,
    policy_hash: Optional[str] = None,
    rate_context: Optional[dict] = None,
    operator: Optional[str] = None,
    agent_id: Optional[str] = None,
    service_account: Optional[str] = None,
    role: Optional[str] = None,
    # MODIFY fields (Phase 7.5)
    original_tool_call: Optional[dict] = None,
    modified_tool_call: Optional[dict] = None,
    modification_rule: Optional[dict] = None,
    reinvocation_verdict: Optional[str] = None,
) -> None:
    record = AuditRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_name=tool_name,
        arguments=arguments,
        verdict=verdict,
        tier=tier,
        reason=reason,
        msg_id=msg_id,
        vault_path=vault_path,
        duration_ms=duration_ms,
        policy_hash=policy_hash,
        rate_context=rate_context,
        operator=operator,
        agent_id=agent_id,
        service_account=service_account,
        role=role,
        original_tool_call=original_tool_call,
        modified_tool_call=modified_tool_call,
        modification_rule=modification_rule,
        reinvocation_verdict=reinvocation_verdict,
    )
    self.log(record)
```

---

## Test Cases

### File: `tests/test_audit_modify.py` (NEW)

```
test_audit_record_has_modify_fields
    record = AuditRecord(timestamp=..., tool_name="chmod", arguments={},
        verdict="modify", tier="destructive", reason="clamped",
        original_tool_call={"tool": "bash", "input": {"command": "chmod 777 f"}},
        modified_tool_call={"tool": "bash", "input": {"command": "chmod 755 f"}},
        modification_rule={"rule_id": "chmod-modify", "operations_applied": [...]},
        reinvocation_verdict="allow")
    -> all four fields accessible and correct

test_audit_record_modify_fields_default_none
    record = AuditRecord(timestamp=..., tool_name="rm", arguments={},
        verdict="allow", tier="destructive", reason="allowed")
    -> original_tool_call is None, modified_tool_call is None, etc.

test_to_json_includes_modify_fields
    record with modification data
    json_str = record.to_json()
    parsed = json.loads(json_str)
    -> "original_tool_call" in parsed
    -> "modified_tool_call" in parsed

test_to_json_omits_none_modify_fields
    record without modification data
    json_str = record.to_json()
    parsed = json.loads(json_str)
    -> "original_tool_call" not in parsed

test_hash_includes_modify_fields
    record_with = AuditRecord(..., original_tool_call={...})
    record_without = AuditRecord(..., original_tool_call=None)
    -> record_with.compute_hash() != record_without.compute_hash()

test_hash_chain_with_modify_record
    logger = AuditLogger(temp_path)
    logger.log_tool_call(..., original_tool_call={...}, modified_tool_call={...})
    logger.log_tool_call(...) # normal record
    valid, count, error = verify_chain(temp_path)
    -> valid is True, count == 2

test_log_tool_call_accepts_modify_params
    logger = AuditLogger(temp_path)
    logger.log_tool_call(
        tool_name="chmod", arguments={"command": "chmod 777 f"},
        verdict="modify", tier="destructive", reason="clamped",
        original_tool_call={"tool": "bash"},
        modified_tool_call={"tool": "bash"},
        modification_rule={"rule_id": "test"},
        reinvocation_verdict="allow")
    -> no error, record written to file

test_backward_compat_existing_log_calls
    Existing log_tool_call() calls without modify params
    -> still work, no error

test_arguments_field_is_original
    Record with verdict="modify", arguments={"command": "chmod 777 f"}
    -> arguments always holds what the agent originally submitted

test_verify_chain_with_mixed_records
    Logger writes: allow record, modify record, deny record
    verify_chain()
    -> valid, 3 records checked
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_audit_modify.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all existing tests pass, ~10 new tests pass
```

---

## Commit

```
Phase 7.5: Audit logger MODIFY record fields

Modified: agent_gate/audit.py
- AuditRecord gains four Optional fields: original_tool_call,
  modified_tool_call, modification_rule, reinvocation_verdict
- log_tool_call() accepts corresponding parameters
- Hash chaining unchanged (sort_keys=True handles new fields)
- Backward compatible: existing calls work without new params
- ~10 new tests in tests/test_audit_modify.py
```
