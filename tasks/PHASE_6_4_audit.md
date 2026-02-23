# Phase 6.4: Audit Logger — Identity Fields

**File:** `audit.py`
**Depends on:** Phase 6.1 (identity.py)
**Parallel with:** Phase 6.3 (gate.py), Phase 6.5 (opa + rego)

---

## Before You Start

```bash
cat audit.py             # Current AuditRecord and AuditLogger
cat identity.py          # Phase 6.1 output — IdentityContext
cat test_audit.py        # Existing audit test patterns
cat test_audit_hash.py   # Hash chain verification tests
```

---

## Context

The AuditRecord needs three new optional fields to bind identity to every decision.  These fields answer "who authorized this?" for the AARM R6 requirement and the NIST AU-10 (non-repudiation) improvement.

Critical constraint: new fields are Optional.  Existing records without identity fields remain valid.  The hash chain continues to work — new fields are included in the hash when present, absent when not.  Chain verification must handle both old (no identity) and new (with identity) records.

---

## Deliverables

### `audit.py` Changes

```python
@dataclass
class AuditRecord:
    # Existing fields unchanged...
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

    # NEW identity fields:
    operator: Optional[str] = None
    agent_id: Optional[str] = None
    service_account: Optional[str] = None
    role: Optional[str] = None

    # Note: session_id already exists.
    # It was previously proxy-generated.
    # Now it can also come from IdentityContext.
    # No structural change needed — just populate from identity.


class AuditLogger:
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
        # NEW parameters:
        operator: Optional[str] = None,
        agent_id: Optional[str] = None,
        service_account: Optional[str] = None,
        role: Optional[str] = None,
    ) -> None:
        """
        Convenience method to log a tool call with common fields.

        Updated to accept identity fields.  All identity params
        are optional for backward compatibility.
        """
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
        )
        self.log(record)
```

### No changes to:
- `_content_for_hashing()` — already dynamically includes all non-None fields
- `compute_hash()` — uses `_content_for_hashing()`, so new fields are automatically included
- `to_json()` — already serializes all non-None fields
- `verify_chain()` — already handles arbitrary fields via dynamic dict construction
- `_chain_record()` — unchanged

The existing hash chain design is elegant: because `_content_for_hashing()` includes all non-None fields except `record_hash`, new fields are automatically part of the hash without code changes.

---

## Test Cases

### File: `test_audit_identity.py` (NEW)

```
# --- Backward Compatibility ---

test_audit_record_no_identity_fields
    Create AuditRecord without identity fields
    → operator, agent_id, service_account, role are all None
    → to_json() does not include identity keys
    → Hash chain works normally

test_existing_hash_chain_valid_after_upgrade
    Write records without identity, then records with identity
    → verify_chain() returns (True, N, None)

# --- Identity Field Serialization ---

test_audit_record_with_operator
    record = AuditRecord(..., operator="sean")
    json_str = record.to_json()
    parsed = json.loads(json_str)
    → parsed["operator"] == "sean"
    → "agent_id" not in parsed (None fields omitted)

test_audit_record_with_all_identity
    record = AuditRecord(
        ..., operator="sean", agent_id="claude-001",
        service_account="ci", role="admin"
    )
    parsed = json.loads(record.to_json())
    → all four identity fields present

test_audit_record_identity_in_hash
    r1 = AuditRecord(..., operator="sean")
    r2 = AuditRecord(...)  # same but no operator
    → r1.compute_hash() != r2.compute_hash()
    (identity fields affect the hash)

# --- log_tool_call with identity ---

test_log_tool_call_with_identity
    logger.log_tool_call(
        ..., operator="sean", role="admin"
    )
    → Last line in log file contains "operator":"sean"

test_log_tool_call_without_identity_backward_compat
    logger.log_tool_call(
        ..., # no identity params
    )
    → Log entry has no identity fields (same as v0.2.0)

# --- Hash Chain with Mixed Records ---

test_chain_mixed_identity_and_no_identity
    Write 3 records without identity
    Write 3 records with identity
    → verify_chain() returns (True, 6, None)

test_chain_integrity_identity_fields_tampered
    Write record with operator="sean"
    Tamper: change operator to "attacker"
    → verify_chain() detects mismatch

# --- Edge Cases ---

test_identity_fields_with_special_characters
    operator="sean o'connor", role="admin & manager"
    → JSON serialization handles special chars correctly
    → Hash chain intact
```

---

## Verification

```bash
python -m pytest test_audit_identity.py -v
python -m pytest test_audit.py test_audit_hash.py -v  # Existing tests
python -m pytest -x -q  # All tests
# Expected: all existing + ~10 new pass
```

---

## Commit

```
Phase 6.4: Audit logger identity fields

- AuditRecord: operator, agent_id, service_account, role fields
- log_tool_call(): accepts identity parameters
- Identity fields included in hash chain automatically
- Mixed chains (old records + new records) verify correctly
- 10 new tests in test_audit_identity.py
- All existing audit and hash chain tests pass
```
