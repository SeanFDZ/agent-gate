"""
Tests for Agent Gate MCP Proxy — MODIFY verdict handling.

Tests cover:
  - Reinvocation loop (MODIFY -> ALLOW, MODIFY -> DENY, etc.)
  - Combined audit record with all four MODIFY fields
  - Depth cap (MODIFY on reinvocation -> DENY)
  - Message rebuilding for forwarding modified calls
  - Non-MODIFY paths remain unchanged
  - _audit_decision helper for non-MODIFY verdicts
  - No vault awareness in the proxy
"""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.mcp_jsonrpc import (
    MCPMessage,
    parse_message,
    GATE_DENIED,
)
from agent_gate.mcp_proxy import MCPProxy, _log
from agent_gate.proxy_config import ProxyConfig
from agent_gate.audit import AuditLogger
from agent_gate.gate import Verdict


# --- Helpers ---

class MockTier:
    def __init__(self, value):
        self.value = value


class MockClassification:
    def __init__(self, tier_value="destructive"):
        self.tier = MockTier(tier_value)


class MockDecision:
    """Mimics GateDecision for proxy testing."""
    def __init__(
        self,
        verdict,
        reason="test reason",
        tier_value="destructive",
        modified_tool_call=None,
        modification_feedback=None,
    ):
        self.verdict = verdict
        self.reason = reason
        self.classification = MockClassification(tier_value)
        self.vault_result = None
        self.modified_tool_call = modified_tool_call
        self.modification_feedback = modification_feedback
        self.escalation_path = None


def _make_proxy(tmpdir):
    """Build an MCPProxy with a mocked Gate for unit testing."""
    policy_path = os.path.join(tmpdir, "policy.yaml")
    with open(policy_path, "w") as f:
        f.write("""
gate:
  name: test-proxy
  version: "1.0"
envelope:
  allowed_paths:
    - /tmp
vault:
  path: {tmpdir}/vault/
  enabled: true
actions:
  destructive: []
  read_only: []
  blocked: []
gate_behavior:
  unclassified: escalate
  vault_failure: deny
""".format(tmpdir=tmpdir))

    config = ProxyConfig(
        policy=policy_path,
        workdir=tmpdir,
        audit_log=os.path.join(tmpdir, "audit.jsonl"),
    )

    proxy = MCPProxy(
        server_command=["echo", "test"],
        config=config,
        server_name="test-server",
    )

    proxy.gate = MagicMock()
    proxy.gate.policy.policy_hash = "testhash1234"
    proxy.gate.rate_tracker.get_rate_context.return_value = {}
    proxy.audit = AuditLogger(
        os.path.join(tmpdir, "audit.jsonl"),
        server_name="test",
        session_id="test-session",
    )

    return proxy


def _make_tool_call_msg(name="bash", arguments=None):
    """Create a tools/call MCPMessage."""
    return parse_message({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })


def _read_audit_records(tmpdir):
    """Read all audit records from the test audit log."""
    audit_path = os.path.join(tmpdir, "audit.jsonl")
    if not os.path.exists(audit_path):
        return []
    with open(audit_path) as f:
        return [json.loads(line) for line in f if line.strip()]


class TestModifyVerdictTriggersReinvocation(unittest.TestCase):
    """MODIFY verdict triggers the reinvocation loop."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_verdict_triggers_reinvocation(self):
        """MODIFY then ALLOW -> forward to server (return None)."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            reason="Permission clamped",
            modified_tool_call=modified_call,
            modification_feedback={
                "policy_rule": "chmod-modify",
                "reason": "Clamped to 755",
                "operations_applied": ["clamp_permission"],
            },
        )
        allow_decision = MockDecision(Verdict.ALLOW, reason="OK")

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]

        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNone(result)  # Forward to server
        self.assertEqual(proxy.gate.evaluate.call_count, 2)

    def test_modify_reinvocation_uses_reinvocation_flag(self):
        """Second gate.evaluate() called with reinvocation=True."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]

        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        proxy._handle_tool_call(msg)

        # First call: no reinvocation flag
        first_call = proxy.gate.evaluate.call_args_list[0]
        self.assertNotIn("reinvocation", first_call.kwargs)

        # Second call: reinvocation=True
        second_call = proxy.gate.evaluate.call_args_list[1]
        self.assertEqual(second_call[0][0], modified_call)
        self.assertTrue(second_call[1].get("reinvocation", False))


class TestModifyAuditRecord(unittest.TestCase):
    """MODIFY audit records have all required fields."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_audit_record_has_all_fields(self):
        """Audit record includes original_tool_call, modified_tool_call,
        modification_rule, reinvocation_verdict."""
        proxy = _make_proxy(self.tmpdir)

        original_input = {"command": "chmod 777 f"}
        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}

        modify_decision = MockDecision(
            Verdict.MODIFY,
            reason="Clamped",
            modified_tool_call=modified_call,
            modification_feedback={
                "policy_rule": "chmod-modify",
                "reason": "Permission clamped",
                "operations_applied": ["clamp_permission"],
            },
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]
        msg = _make_tool_call_msg("bash", original_input)
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        records = _read_audit_records(self.tmpdir)
        self.assertEqual(len(records), 1)

        r = records[0]
        self.assertIn("original_tool_call", r)
        self.assertIn("modified_tool_call", r)
        self.assertIn("modification_rule", r)
        self.assertIn("reinvocation_verdict", r)
        self.assertEqual(r["reinvocation_verdict"], "allow")

    def test_modify_arguments_field_is_original(self):
        """The 'arguments' field in the audit record is the original input."""
        proxy = _make_proxy(self.tmpdir)

        original_input = {"command": "chmod 777 f"}
        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}

        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]
        msg = _make_tool_call_msg("bash", original_input)
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        records = _read_audit_records(self.tmpdir)
        self.assertEqual(records[0]["arguments"], original_input)

    def test_modify_audit_verdict_field(self):
        """Audit verdict is 'modify' when reinvocation returns ALLOW."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        records = _read_audit_records(self.tmpdir)
        self.assertEqual(records[0]["verdict"], "modify")

    def test_modify_single_audit_record(self):
        """Only one audit record is written for a MODIFY flow, not two."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        records = _read_audit_records(self.tmpdir)
        tool_records = [
            r for r in records if r["tool_name"] == "bash"
        ]
        self.assertEqual(len(tool_records), 1)

    def test_modify_duration_includes_reinvocation(self):
        """duration_ms covers both evaluations."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}

        def slow_evaluate(*args, **kwargs):
            time.sleep(0.01)
            return allow_decision

        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                time.sleep(0.01)
                return modify_decision
            time.sleep(0.01)
            return allow_decision

        proxy.gate.evaluate.side_effect = side_effect
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        records = _read_audit_records(self.tmpdir)
        # Duration should cover both evaluations (>= 20ms)
        self.assertGreaterEqual(records[0]["duration_ms"], 15)


class TestModifyReinvocationDeny(unittest.TestCase):
    """Reinvocation returning DENY."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_reinvocation_deny(self):
        """MODIFY then DENY -> denial response."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "rm file"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        deny_decision = MockDecision(Verdict.DENY, reason="Still blocked")

        proxy.gate.evaluate.side_effect = [modify_decision, deny_decision]
        msg = _make_tool_call_msg("bash", {"command": "rm -f file"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)
        self.assertIn("error", result)

        # Audit should show reinvocation_verdict="deny"
        proxy.audit.close()
        records = _read_audit_records(self.tmpdir)
        self.assertEqual(records[0]["reinvocation_verdict"], "deny")
        self.assertEqual(records[0]["verdict"], "deny")


class TestModifyDepthCap(unittest.TestCase):
    """MODIFY on reinvocation -> DENY (depth cap)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_reinvocation_modify_depth_cap(self):
        """MODIFY on both calls -> depth cap -> denial."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision1 = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        modify_decision2 = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )

        proxy.gate.evaluate.side_effect = [modify_decision1, modify_decision2]
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)
        self.assertIn("error", result)

        proxy.audit.close()
        records = _read_audit_records(self.tmpdir)
        self.assertEqual(records[0]["reinvocation_verdict"], "modify")
        self.assertEqual(records[0]["verdict"], "deny")


class TestModifyEscalateTreatedAsDeny(unittest.TestCase):
    """MODIFY then ESCALATE -> treated as deny."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_reinvocation_escalate_treated_as_deny(self):
        """MODIFY then ESCALATE -> denial."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "curl example.com"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        escalate_decision = MockDecision(Verdict.ESCALATE, reason="Needs approval")

        proxy.gate.evaluate.side_effect = [modify_decision, escalate_decision]
        msg = _make_tool_call_msg("bash", {"command": "curl example.com"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)

        proxy.audit.close()
        records = _read_audit_records(self.tmpdir)
        self.assertEqual(records[0]["reinvocation_verdict"], "escalate")
        self.assertEqual(records[0]["verdict"], "deny")


class TestModifyReinvocationError(unittest.TestCase):
    """Reinvocation raises an exception."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_reinvocation_error(self):
        """MODIFY then exception -> denial with error verdict."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return modify_decision
            raise RuntimeError("OPA crashed")

        proxy.gate.evaluate.side_effect = side_effect
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)

        proxy.audit.close()
        records = _read_audit_records(self.tmpdir)
        self.assertEqual(records[0]["reinvocation_verdict"], "error")
        self.assertEqual(records[0]["verdict"], "deny")


class TestModifyMissingModifiedToolCall(unittest.TestCase):
    """MODIFY with modified_tool_call=None."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_missing_modified_tool_call(self):
        """MODIFY without modified_tool_call -> error response."""
        proxy = _make_proxy(self.tmpdir)

        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=None,
        )

        proxy.gate.evaluate.return_value = modify_decision
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)
        self.assertIn("error", result)
        self.assertIn("missing modified_tool_call", result["error"]["message"])


class TestModifyForwardsModifiedMessage(unittest.TestCase):
    """Forwarded message uses modified params."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_modify_forwards_modified_message(self):
        """After MODIFY+ALLOW, msg.raw has modified params."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]

        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNone(result)
        # Verify the raw message was rebuilt with modified params
        self.assertEqual(
            msg.raw["params"]["arguments"]["command"],
            "chmod 755 f",
        )


class TestRebuildToolCallMessage(unittest.TestCase):
    """Test _rebuild_tool_call_message directly."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_rebuild_tool_call_message(self):
        """Rebuilds params with modified input."""
        proxy = _make_proxy(self.tmpdir)

        original_raw = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {"command": "chmod 777 f"}},
        }
        modified = {"input": {"command": "chmod 755 f"}}

        rebuilt = proxy._rebuild_tool_call_message(original_raw, modified)
        self.assertEqual(
            rebuilt["params"]["arguments"]["command"],
            "chmod 755 f",
        )
        # Original should not be mutated
        self.assertEqual(
            original_raw["params"]["arguments"]["command"],
            "chmod 777 f",
        )

    def test_rebuild_with_input_key(self):
        """Rebuilds when params uses 'input' instead of 'arguments'."""
        proxy = _make_proxy(self.tmpdir)

        original_raw = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"input": {"command": "chmod 777 f"}},
        }
        modified = {"input": {"command": "chmod 755 f"}}

        rebuilt = proxy._rebuild_tool_call_message(original_raw, modified)
        self.assertEqual(
            rebuilt["params"]["input"]["command"],
            "chmod 755 f",
        )


class TestNonModifyPathsUnchanged(unittest.TestCase):
    """Non-MODIFY paths remain unchanged."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_non_modify_path_unchanged(self):
        """ALLOW verdict -> no reinvocation, normal path."""
        proxy = _make_proxy(self.tmpdir)

        allow_decision = MockDecision(Verdict.ALLOW, reason="OK", tier_value="read_only")
        proxy.gate.evaluate.return_value = allow_decision

        msg = _make_tool_call_msg("read_file", {"path": "/tmp/x"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNone(result)
        self.assertEqual(proxy.gate.evaluate.call_count, 1)

    def test_deny_path_unchanged(self):
        """DENY verdict -> denial response, no reinvocation."""
        proxy = _make_proxy(self.tmpdir)

        deny_decision = MockDecision(Verdict.DENY, reason="Blocked", tier_value="blocked")
        proxy.gate.evaluate.return_value = deny_decision

        msg = _make_tool_call_msg("rm", {"path": "/"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)
        self.assertIn("error", result)
        self.assertEqual(proxy.gate.evaluate.call_count, 1)

    def test_escalate_path_unchanged(self):
        """ESCALATE verdict -> escalation response, no reinvocation."""
        proxy = _make_proxy(self.tmpdir)

        escalate_decision = MockDecision(
            Verdict.ESCALATE, reason="Needs approval", tier_value="network"
        )
        proxy.gate.evaluate.return_value = escalate_decision

        msg = _make_tool_call_msg("curl", {"url": "http://example.com"})
        result = proxy._handle_tool_call(msg)

        self.assertIsNotNone(result)
        self.assertEqual(proxy.gate.evaluate.call_count, 1)


class TestAuditDecisionHelper(unittest.TestCase):
    """Test _audit_decision helper for non-MODIFY verdicts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_audit_decision_helper_non_modify(self):
        """_audit_decision writes a record without modify fields."""
        proxy = _make_proxy(self.tmpdir)

        allow_decision = MockDecision(Verdict.ALLOW, reason="OK", tier_value="read_only")
        proxy._audit_decision(
            allow_decision, "read_file", {"path": "/tmp/x"}, 1, 5.0
        )
        proxy.audit.close()

        records = _read_audit_records(self.tmpdir)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["verdict"], "allow")
        self.assertNotIn("original_tool_call", r)
        self.assertNotIn("modified_tool_call", r)
        self.assertNotIn("modification_rule", r)
        self.assertNotIn("reinvocation_verdict", r)


class TestProxyHasNoVaultAwareness(unittest.TestCase):
    """Verify MCPProxy has no vault-related attributes or methods."""

    def test_proxy_has_no_vault_awareness(self):
        """MCPProxy class has no vault-related attributes or methods."""
        # Check the class source for vault references
        import inspect
        source = inspect.getsource(MCPProxy)

        # The proxy should reference vault_result only when reading
        # from a GateDecision (in _audit_decision), not own any vault logic.
        # It should NOT import VaultManager or have vault config.
        from agent_gate import mcp_proxy
        module_source = inspect.getsource(mcp_proxy)
        self.assertNotIn("VaultManager", module_source)
        self.assertNotIn("from agent_gate.vault", module_source)


class TestModifyLogMessages(unittest.TestCase):
    """Verify log messages contain expected strings."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch('agent_gate.mcp_proxy._log')
    def test_modify_log_message(self, mock_log):
        """Log output includes MODIFY and MODIFY+ALLOW."""
        proxy = _make_proxy(self.tmpdir)

        modified_call = {"tool": "bash", "input": {"command": "chmod 755 f"}}
        modify_decision = MockDecision(
            Verdict.MODIFY,
            modified_tool_call=modified_call,
        )
        allow_decision = MockDecision(Verdict.ALLOW)

        proxy.gate.evaluate.side_effect = [modify_decision, allow_decision]
        msg = _make_tool_call_msg("bash", {"command": "chmod 777 f"})
        proxy._handle_tool_call(msg)

        log_messages = [str(c) for c in mock_log.call_args_list]
        all_logs = " ".join(log_messages)
        self.assertIn("MODIFY", all_logs)
        self.assertIn("MODIFY+ALLOW", all_logs)


if __name__ == "__main__":
    unittest.main()
