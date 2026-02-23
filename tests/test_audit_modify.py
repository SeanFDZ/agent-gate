"""
Tests for Phase 7.5: Audit Logger MODIFY record fields.

Verifies that AuditRecord accepts four new Optional fields for MODIFY
decisions,  that log_tool_call() passes them through,  and that the
hash chain remains intact with mixed record types.
"""

import json
import os
import tempfile

import pytest

from agent_gate.audit import AuditRecord, AuditLogger, verify_chain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_modify_record(**overrides):
    """Build an AuditRecord with MODIFY fields populated."""
    defaults = dict(
        timestamp="2026-02-23T00:00:00+00:00",
        tool_name="chmod",
        arguments={"command": "chmod 777 deploy.sh"},
        verdict="modify",
        tier="destructive",
        reason="Permission clamped to 755",
        original_tool_call={
            "tool": "bash",
            "input": {"command": "chmod 777 deploy.sh"},
        },
        modified_tool_call={
            "tool": "bash",
            "input": {"command": "chmod 755 deploy.sh"},
        },
        modification_rule={
            "rule_id": "chmod-clamp-prod",
            "description": "Clamp permission to 755",
            "operations_applied": ["clamp_permission"],
        },
        reinvocation_verdict="allow",
    )
    defaults.update(overrides)
    return AuditRecord(**defaults)


def _make_plain_record(**overrides):
    """Build a normal (non-MODIFY) AuditRecord."""
    defaults = dict(
        timestamp="2026-02-23T00:00:01+00:00",
        tool_name="ls",
        arguments={"path": "/tmp"},
        verdict="allow",
        tier="read_only",
        reason="Read-only tool allowed",
    )
    defaults.update(overrides)
    return AuditRecord(**defaults)


# ---------------------------------------------------------------------------
# test_audit_record_has_modify_fields
# ---------------------------------------------------------------------------

def test_audit_record_has_modify_fields():
    """MODIFY fields are accessible and hold correct values."""
    record = _make_modify_record()
    assert record.original_tool_call == {
        "tool": "bash",
        "input": {"command": "chmod 777 deploy.sh"},
    }
    assert record.modified_tool_call == {
        "tool": "bash",
        "input": {"command": "chmod 755 deploy.sh"},
    }
    assert record.modification_rule["rule_id"] == "chmod-clamp-prod"
    assert record.reinvocation_verdict == "allow"


# ---------------------------------------------------------------------------
# test_audit_record_modify_fields_default_none
# ---------------------------------------------------------------------------

def test_audit_record_modify_fields_default_none():
    """MODIFY fields default to None for non-MODIFY records."""
    record = _make_plain_record()
    assert record.original_tool_call is None
    assert record.modified_tool_call is None
    assert record.modification_rule is None
    assert record.reinvocation_verdict is None


# ---------------------------------------------------------------------------
# test_to_json_includes_modify_fields
# ---------------------------------------------------------------------------

def test_to_json_includes_modify_fields():
    """to_json() includes MODIFY fields when they are set."""
    record = _make_modify_record()
    parsed = json.loads(record.to_json())
    assert "original_tool_call" in parsed
    assert "modified_tool_call" in parsed
    assert "modification_rule" in parsed
    assert "reinvocation_verdict" in parsed
    assert parsed["reinvocation_verdict"] == "allow"


# ---------------------------------------------------------------------------
# test_to_json_omits_none_modify_fields
# ---------------------------------------------------------------------------

def test_to_json_omits_none_modify_fields():
    """to_json() omits MODIFY fields when they are None."""
    record = _make_plain_record()
    parsed = json.loads(record.to_json())
    assert "original_tool_call" not in parsed
    assert "modified_tool_call" not in parsed
    assert "modification_rule" not in parsed
    assert "reinvocation_verdict" not in parsed


# ---------------------------------------------------------------------------
# test_hash_includes_modify_fields
# ---------------------------------------------------------------------------

def test_hash_includes_modify_fields():
    """Hash differs between records with and without MODIFY data."""
    record_with = _make_modify_record()
    record_without = AuditRecord(
        timestamp=record_with.timestamp,
        tool_name=record_with.tool_name,
        arguments=record_with.arguments,
        verdict=record_with.verdict,
        tier=record_with.tier,
        reason=record_with.reason,
    )
    assert record_with.compute_hash() != record_without.compute_hash()


# ---------------------------------------------------------------------------
# test_hash_chain_with_modify_record
# ---------------------------------------------------------------------------

def test_hash_chain_with_modify_record(tmp_path):
    """Hash chain stays valid when MODIFY records are in the log."""
    log_path = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(log_path)
    logger.log_tool_call(
        tool_name="chmod",
        arguments={"command": "chmod 777 deploy.sh"},
        verdict="modify",
        tier="destructive",
        reason="Permission clamped to 755",
        original_tool_call={"tool": "bash", "input": {"command": "chmod 777 deploy.sh"}},
        modified_tool_call={"tool": "bash", "input": {"command": "chmod 755 deploy.sh"}},
        modification_rule={"rule_id": "chmod-clamp-prod"},
        reinvocation_verdict="allow",
    )
    logger.log_tool_call(
        tool_name="ls",
        arguments={"path": "/tmp"},
        verdict="allow",
        tier="read_only",
        reason="Allowed",
    )
    logger.close()

    valid, count, error = verify_chain(log_path)
    assert valid is True
    assert count == 2
    assert error is None


# ---------------------------------------------------------------------------
# test_log_tool_call_accepts_modify_params
# ---------------------------------------------------------------------------

def test_log_tool_call_accepts_modify_params(tmp_path):
    """log_tool_call() accepts all four MODIFY parameters without error."""
    log_path = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(log_path)
    logger.log_tool_call(
        tool_name="chmod",
        arguments={"command": "chmod 777 f"},
        verdict="modify",
        tier="destructive",
        reason="clamped",
        original_tool_call={"tool": "bash"},
        modified_tool_call={"tool": "bash"},
        modification_rule={"rule_id": "test"},
        reinvocation_verdict="allow",
    )
    logger.close()

    # Verify the record was written
    with open(log_path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["original_tool_call"] == {"tool": "bash"}
    assert parsed["reinvocation_verdict"] == "allow"


# ---------------------------------------------------------------------------
# test_backward_compat_existing_log_calls
# ---------------------------------------------------------------------------

def test_backward_compat_existing_log_calls(tmp_path):
    """Existing log_tool_call() calls without MODIFY params still work."""
    log_path = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(log_path)
    logger.log_tool_call(
        tool_name="rm",
        arguments={"command": "rm file.txt"},
        verdict="allow",
        tier="destructive",
        reason="Allowed by policy",
    )
    logger.close()

    with open(log_path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert "original_tool_call" not in parsed
    assert parsed["verdict"] == "allow"


# ---------------------------------------------------------------------------
# test_arguments_field_is_original
# ---------------------------------------------------------------------------

def test_arguments_field_is_original():
    """The arguments field always holds what the agent originally submitted."""
    record = _make_modify_record()
    # arguments is the original submission
    assert record.arguments == {"command": "chmod 777 deploy.sh"}
    # modified_tool_call carries the rewrite
    assert record.modified_tool_call["input"]["command"] == "chmod 755 deploy.sh"


# ---------------------------------------------------------------------------
# test_verify_chain_with_mixed_records
# ---------------------------------------------------------------------------

def test_verify_chain_with_mixed_records(tmp_path):
    """Chain verification passes with allow, modify, and deny records."""
    log_path = str(tmp_path / "audit.jsonl")
    logger = AuditLogger(log_path)

    # Record 1: allow
    logger.log_tool_call(
        tool_name="ls",
        arguments={"path": "."},
        verdict="allow",
        tier="read_only",
        reason="Read-only allowed",
    )

    # Record 2: modify
    logger.log_tool_call(
        tool_name="chmod",
        arguments={"command": "chmod 777 f"},
        verdict="modify",
        tier="destructive",
        reason="Clamped",
        original_tool_call={"tool": "bash", "input": {"command": "chmod 777 f"}},
        modified_tool_call={"tool": "bash", "input": {"command": "chmod 755 f"}},
        modification_rule={"rule_id": "clamp", "operations_applied": ["clamp_permission"]},
        reinvocation_verdict="allow",
    )

    # Record 3: deny
    logger.log_tool_call(
        tool_name="rm",
        arguments={"command": "rm -rf /"},
        verdict="deny",
        tier="blocked",
        reason="Blocked by policy",
    )

    logger.close()

    valid, count, error = verify_chain(log_path)
    assert valid is True
    assert count == 3
    assert error is None
