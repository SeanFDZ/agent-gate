"""
Agent Gate — CLI Tree Command Tests
Tests for the `agent-gate tree` subcommand that displays
agent session hierarchy from audit log JSONL data.
"""

import io
import json
import os
import sys
import tempfile
from types import SimpleNamespace

# Ensure imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.cli import cmd_tree


def _write_jsonl(records, path):
    """Write a list of dicts as JSONL to the given path."""
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _capture_tree(session_id, log_path):
    """Run cmd_tree and capture stdout."""
    args = SimpleNamespace(session_id=session_id, log=log_path)
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        cmd_tree(args)
        return sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout


def run_tests():
    passed = 0
    failed = 0

    def test(name, fn):
        nonlocal passed, failed
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1

    # --- Test: Single session, no sub-agents ---
    def test_single_session():
        records = [
            {"agent_id": "sess-001", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "sess-001", "agent_depth": 0, "verdict": "allow", "tool_name": "Write"},
            {"agent_id": "sess-001", "agent_depth": 0, "verdict": "deny", "tool_name": "Bash"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("sess-001", path)
            assert "Session: sess-001" in out, f"Missing session header in: {out!r}"
            assert "depth=0" in out, f"Missing depth=0 in: {out!r}"
            assert "allow: 2" in out, f"Missing allow: 2 in: {out!r}"
            assert "deny: 1" in out, f"Missing deny: 1 in: {out!r}"
            assert "Sub-agent" not in out, f"Unexpected sub-agent in: {out!r}"
        finally:
            os.unlink(path)

    test("Single session, no sub-agents", test_single_session)

    # --- Test: Two-level hierarchy ---
    def test_two_level():
        records = [
            {"agent_id": "parent-01", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "parent-01", "agent_depth": 0, "verdict": "deny", "tool_name": "Write"},
            {"agent_id": "child-01", "agent_depth": 1, "parent_agent_id": "parent-01",
             "inherited_policy": True, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "child-01", "agent_depth": 1, "parent_agent_id": "parent-01",
             "inherited_policy": True, "verdict": "deny", "tool_name": "Write"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("parent-01", path)
            assert "Session: parent-01" in out, f"Missing parent header in: {out!r}"
            assert "Sub-agent: child-01" in out, f"Missing child in: {out!r}"
            assert "depth=1" in out, f"Missing depth=1 in: {out!r}"
            assert "inherited_policy=True" in out, f"Missing inherited_policy in: {out!r}"
            # Child should be indented
            lines = out.strip().split("\n")
            child_line = [l for l in lines if "Sub-agent: child-01" in l][0]
            assert child_line.strip().startswith("\u2514\u2500\u2500") or child_line.strip().startswith("\u251c\u2500\u2500"), \
                f"Child not properly indented: {child_line!r}"
        finally:
            os.unlink(path)

    test("Two-level hierarchy", test_two_level)

    # --- Test: Three-level hierarchy ---
    def test_three_level():
        records = [
            {"agent_id": "root", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "mid", "agent_depth": 1, "parent_agent_id": "root",
             "inherited_policy": True, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "leaf", "agent_depth": 2, "parent_agent_id": "mid",
             "inherited_policy": True, "verdict": "deny", "tool_name": "Write"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("root", path)
            assert "Session: root" in out, f"Missing root in: {out!r}"
            assert "Sub-agent: mid" in out, f"Missing mid in: {out!r}"
            assert "Sub-agent: leaf" in out, f"Missing leaf in: {out!r}"
            assert "depth=2" in out, f"Missing depth=2 in: {out!r}"
        finally:
            os.unlink(path)

    test("Three-level hierarchy", test_three_level)

    # --- Test: Multiple children at same level ---
    def test_multiple_children():
        records = [
            {"agent_id": "parent", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "child-a", "agent_depth": 1, "parent_agent_id": "parent",
             "inherited_policy": True, "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "child-b", "agent_depth": 1, "parent_agent_id": "parent",
             "inherited_policy": True, "verdict": "deny", "tool_name": "Write"},
            {"agent_id": "child-c", "agent_depth": 1, "parent_agent_id": "parent",
             "inherited_policy": True, "verdict": "allow", "tool_name": "Read"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("parent", path)
            lines = out.strip().split("\n")
            # Find lines with child connectors
            child_lines = [l for l in lines if "Sub-agent:" in l]
            assert len(child_lines) == 3, f"Expected 3 children, got {len(child_lines)}: {child_lines}"
            # Non-last children use ├──, last child uses └──
            assert "\u251c\u2500\u2500" in child_lines[0], f"First child missing ├──: {child_lines[0]!r}"
            assert "\u251c\u2500\u2500" in child_lines[1], f"Second child missing ├──: {child_lines[1]!r}"
            assert "\u2514\u2500\u2500" in child_lines[2], f"Last child missing └──: {child_lines[2]!r}"
        finally:
            os.unlink(path)

    test("Multiple children at same level", test_multiple_children)

    # --- Test: Records without agent_id ---
    def test_no_agent_id():
        records = [
            {"agent_id": "sess-x", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"},
            {"verdict": "allow", "tool_name": "Bash"},  # no agent_id
            {"verdict": "deny", "tool_name": "Write"},   # no agent_id
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("sess-x", path)
            assert "2 records have no hierarchy context" in out, f"Missing no-hierarchy summary in: {out!r}"
        finally:
            os.unlink(path)

    test("Records without agent_id counted in summary", test_no_agent_id)

    # --- Test: Session not found ---
    def test_session_not_found():
        records = [
            {"agent_id": "other-sess", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("nonexistent", path)
            assert "Session 'nonexistent' not found in log." in out, f"Wrong message: {out!r}"
        finally:
            os.unlink(path)

    test("Session not found", test_session_not_found)

    # --- Test: Log file not found ---
    def test_log_not_found():
        out = _capture_tree("any-session", "/tmp/nonexistent_gate_log_12345.jsonl")
        assert "Log file not found:" in out, f"Wrong message: {out!r}"

    test("Log file not found", test_log_not_found)

    # --- Test: Malformed JSON lines ---
    def test_malformed_json():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            with open(path, "w") as f:
                f.write('{"agent_id": "sess-m", "agent_depth": 0, "verdict": "allow", "tool_name": "Bash"}\n')
                f.write("this is not json\n")
                f.write("{bad json\n")
                f.write('{"agent_id": "sess-m", "agent_depth": 0, "verdict": "deny", "tool_name": "Write"}\n')
            out = _capture_tree("sess-m", path)
            assert "Session: sess-m" in out, f"Missing session header in: {out!r}"
            assert "allow: 1" in out, f"Missing allow count in: {out!r}"
            assert "deny: 1" in out, f"Missing deny count in: {out!r}"
            assert "2 lines skipped (malformed JSON)." in out, f"Missing malformed summary in: {out!r}"
        finally:
            os.unlink(path)

    test("Malformed JSON lines skipped and counted", test_malformed_json)

    # --- Test: Records with no hierarchy fields (pre-Phase-8A) ---
    def test_pre_phase8a_records():
        # Records that have agent_id but no agent_depth/parent_agent_id/inherited_policy
        records = [
            {"agent_id": "legacy-sess", "verdict": "allow", "tool_name": "Bash"},
            {"agent_id": "legacy-sess", "verdict": "deny", "tool_name": "Write"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            _write_jsonl(records, path)
            out = _capture_tree("legacy-sess", path)
            assert "Session: legacy-sess" in out, f"Missing session header in: {out!r}"
            assert "depth=0" in out, f"Missing depth=0 for legacy records in: {out!r}"
            assert "allow: 1" in out, f"Missing allow count in: {out!r}"
            assert "deny: 1" in out, f"Missing deny count in: {out!r}"
        finally:
            os.unlink(path)

    test("Pre-Phase-8A records appear at depth=0", test_pre_phase8a_records)

    # --- Summary ---
    total = passed + failed
    print(f"\n{passed}/{total} tests passed")
    return failed == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_tests() else 1)
