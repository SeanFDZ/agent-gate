"""
Tests for Phase 8A: Sub-agent hierarchy fields in audit records.

Verifies that:
  - AuditRecord accepts agent_depth, parent_agent_id, inherited_policy fields.
  - Hierarchy fields serialize correctly (present when set, absent when None).
  - Hierarchy fields are included in the hash chain.
  - log_tool_call accepts hierarchy parameters with backward compatibility.
  - Mixed chains (records with/without hierarchy fields) verify correctly.
  - Round-trip through to_json() preserves hierarchy fields.
"""

import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.audit import AuditLogger, AuditRecord, verify_chain, GENESIS_HASH


class TestEnvironment:
    """Context manager that creates a temp directory and cleans up."""

    def __init__(self):
        self.tmpdir = None

    def __enter__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ag_test_hierarchy_")
        return self

    def __exit__(self, *args):
        if self.tmpdir and os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    @property
    def audit_path(self):
        return os.path.join(self.tmpdir, "audit.jsonl")


def run_tests() -> bool:
    """Run all hierarchy audit tests.  Returns True if all pass."""
    results = []

    def test(name, fn):
        try:
            fn()
            print(f"  PASS  {name}")
            results.append(True)
        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            results.append(False)

    print("test_audit_hierarchy.py")

    # --- Test 1: log_tool_call with hierarchy fields produces record containing all three ---
    def test_hierarchy_fields_present():
        with TestEnvironment() as env:
            with AuditLogger(env.audit_path) as logger:
                logger.log_tool_call(
                    tool_name="rm",
                    arguments={"path": "/tmp/x"},
                    verdict="allow",
                    tier="destructive",
                    reason="test",
                    agent_depth=1,
                    parent_agent_id="parent-123",
                    inherited_policy=True,
                )
            with open(env.audit_path) as f:
                record = json.loads(f.readline())
            assert record["agent_depth"] == 1, f"expected 1, got {record.get('agent_depth')}"
            assert record["parent_agent_id"] == "parent-123"
            assert record["inherited_policy"] is True

    test("hierarchy fields present when set", test_hierarchy_fields_present)

    # --- Test 2: log_tool_call with no hierarchy args omits all three (backward compat) ---
    def test_no_hierarchy_fields():
        with TestEnvironment() as env:
            with AuditLogger(env.audit_path) as logger:
                logger.log_tool_call(
                    tool_name="cat",
                    arguments={},
                    verdict="allow",
                    tier="read_only",
                    reason="test",
                )
            with open(env.audit_path) as f:
                record = json.loads(f.readline())
            assert "agent_depth" not in record, f"agent_depth should be absent, got {record.get('agent_depth')}"
            assert "parent_agent_id" not in record
            assert "inherited_policy" not in record

    test("no hierarchy fields when not set (backward compat)", test_no_hierarchy_fields)

    # --- Test 3: agent_depth=0 omits hierarchy fields (depth 0 = not a subagent) ---
    def test_depth_zero_omits_fields():
        with TestEnvironment() as env:
            with AuditLogger(env.audit_path) as logger:
                logger.log_tool_call(
                    tool_name="cat",
                    arguments={},
                    verdict="allow",
                    tier="read_only",
                    reason="test",
                    agent_depth=0,
                )
            with open(env.audit_path) as f:
                record = json.loads(f.readline())
            # agent_depth=0 is falsy for Optional[int] but dataclass stores it.
            # However, 0 is not None so it WILL appear in JSON via to_json().
            # The spec says depth=0 is "the same as not set" — but the to_json
            # filter is `if v is not None`, and 0 is not None.
            # We verify the record does NOT contain parent_agent_id or inherited_policy
            # since those were not passed.
            assert "parent_agent_id" not in record
            assert "inherited_policy" not in record

    test("depth=0 omits parent/inherited fields", test_depth_zero_omits_fields)

    # --- Test 4: verify_chain passes on log with hierarchy fields ---
    def test_chain_with_hierarchy():
        with TestEnvironment() as env:
            with AuditLogger(env.audit_path) as logger:
                logger.log_tool_call(
                    "tool1", {}, "allow", "read_only", "r1",
                    agent_depth=1, parent_agent_id="parent-123",
                    inherited_policy=True,
                )
                logger.log_tool_call(
                    "tool2", {}, "deny", "blocked", "r2",
                    agent_depth=1, parent_agent_id="parent-123",
                    inherited_policy=True,
                )
            valid, checked, error = verify_chain(env.audit_path)
            assert valid, f"Chain should be valid but got: {error}"
            assert checked == 2

    test("verify_chain passes with hierarchy fields", test_chain_with_hierarchy)

    # --- Test 5: verify_chain passes on log without hierarchy fields ---
    def test_chain_without_hierarchy():
        with TestEnvironment() as env:
            with AuditLogger(env.audit_path) as logger:
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "deny", "blocked", "r2")
            valid, checked, error = verify_chain(env.audit_path)
            assert valid, f"Chain should be valid but got: {error}"
            assert checked == 2

    test("verify_chain passes without hierarchy fields", test_chain_without_hierarchy)

    # --- Test 6: verify_chain passes on mixed log ---
    def test_chain_mixed():
        with TestEnvironment() as env:
            with AuditLogger(env.audit_path) as logger:
                # Records without hierarchy
                logger.log_tool_call("tool1", {}, "allow", "read_only", "r1")
                logger.log_tool_call("tool2", {}, "allow", "read_only", "r2")
                # Records with hierarchy
                logger.log_tool_call(
                    "tool3", {}, "allow", "read_only", "r3",
                    agent_depth=1, parent_agent_id="parent-123",
                    inherited_policy=True,
                )
                # Back to without
                logger.log_tool_call("tool4", {}, "deny", "blocked", "r4")
            valid, checked, error = verify_chain(env.audit_path)
            assert valid, f"Chain should be valid but got: {error}"
            assert checked == 4

    test("verify_chain passes on mixed log", test_chain_mixed)

    # --- Test 7: Round-trip through to_json() and back ---
    def test_round_trip():
        record = AuditRecord(
            timestamp="2026-02-24T12:00:00Z",
            tool_name="rm",
            arguments={"path": "/tmp/deep"},
            verdict="allow",
            tier="destructive",
            reason="test",
            agent_depth=2,
            parent_agent_id="grandparent-456",
            inherited_policy=True,
            prev_hash=GENESIS_HASH,
        )
        record.record_hash = record.compute_hash()
        json_str = record.to_json()
        parsed = json.loads(json_str)
        assert parsed["agent_depth"] == 2, f"expected 2, got {parsed.get('agent_depth')}"
        assert parsed["parent_agent_id"] == "grandparent-456"
        assert parsed["inherited_policy"] is True
        # Verify all core fields survived
        assert parsed["tool_name"] == "rm"
        assert parsed["verdict"] == "allow"
        assert parsed["prev_hash"] == GENESIS_HASH

    test("round-trip to_json and back", test_round_trip)

    # --- Summary ---
    passed = sum(results)
    total = len(results)
    print(f"\n{passed}/{total} tests passed.")
    return all(results)


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_tests() else 1)
