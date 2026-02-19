"""
Tests for Agent Gate MCP Proxy.

Tests cover:
  - MCPProxy._handle_tool_call routing (allow, deny, escalate)
  - Gate format translation through the proxy
  - ServerProcess lifecycle
  - CLI argument parsing
  - Audit logging integration
  - Full message routing (mock server)
"""

import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.mcp_jsonrpc import (
    MCPMessage,
    MCPMethod,
    MessageType,
    StdioTransport,
    parse_message,
    GATE_DENIED,
    GATE_ESCALATE,
)
from agent_gate.mcp_proxy import MCPProxy, ServerProcess
from agent_gate.proxy_config import ProxyConfig
from agent_gate.audit import AuditLogger


# --- Mock Gate decision objects ---

class MockTier:
    def __init__(self, value):
        self.value = value

class MockClassification:
    def __init__(self, tier_value):
        self.tier = MockTier(tier_value)

class MockVerdict:
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"

class MockDecision:
    """Mimics GateDecision structure."""
    def __init__(self, verdict_str, reason, tier_value="read_only"):
        # Create a mock verdict enum
        self.verdict = MagicMock()
        self.verdict.value = verdict_str

        # Set comparison behavior
        from agent_gate.gate import Verdict
        if verdict_str == "allow":
            self.verdict.__eq__ = lambda s, other: other == Verdict.ALLOW
        elif verdict_str == "deny":
            self.verdict.__eq__ = lambda s, other: other == Verdict.DENY
        elif verdict_str == "escalate":
            self.verdict.__eq__ = lambda s, other: other == Verdict.ESCALATE

        self.reason = reason
        self.classification = MockClassification(tier_value)
        self.vault_result = None


def _make_proxy_with_mock_gate(gate_mock, tmpdir):
    """Build an MCPProxy with a mocked Gate for unit testing."""
    # Create a minimal valid policy file
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

    # Replace gate with mock
    proxy.gate = gate_mock
    proxy.audit = AuditLogger(
        os.path.join(tmpdir, "audit.jsonl"),
        server_name="test",
        session_id="test-session",
    )

    return proxy


class TestHandleToolCall(unittest.TestCase):
    """Test the proxy's tool call interception and routing."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_tool_call_msg(self, name, arguments=None):
        return parse_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        })

    def test_allow_returns_none(self):
        """ALLOW verdict → None (forward to server)."""
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("allow", "Read-only action", "read_only")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = self._make_tool_call_msg("read_file", {"path": "/tmp/test"})

        result = proxy._handle_tool_call(msg)
        self.assertIsNone(result)
        gate.evaluate.assert_called_once()

    def test_deny_returns_error_response(self):
        """DENY verdict → JSON-RPC error with gate metadata."""
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("deny", "Blocked by policy", "blocked")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = self._make_tool_call_msg("rm", {"path": "/"})

        result = proxy._handle_tool_call(msg)
        self.assertIsNotNone(result)
        self.assertIn("error", result)
        self.assertEqual(result["error"]["code"], GATE_DENIED)
        self.assertEqual(result["error"]["data"]["gate_verdict"], "deny")
        self.assertEqual(result["error"]["data"]["tier"], "blocked")

    def test_escalate_returns_escalation_response(self):
        """ESCALATE verdict → JSON-RPC error with escalation metadata."""
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("escalate", "Requires approval", "network")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = self._make_tool_call_msg("curl", {"url": "http://example.com"})

        result = proxy._handle_tool_call(msg)
        self.assertIsNotNone(result)
        self.assertEqual(result["error"]["code"], GATE_ESCALATE)
        self.assertEqual(result["error"]["data"]["gate_verdict"], "escalate")

    def test_gate_error_fails_closed(self):
        """Gate evaluation error → deny (fail closed)."""
        gate = MagicMock()
        gate.evaluate.side_effect = Exception("Policy engine crashed")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = self._make_tool_call_msg("something", {})

        result = proxy._handle_tool_call(msg)
        self.assertIsNotNone(result)
        self.assertIn("error", result)

    def test_gate_receives_correct_format(self):
        """Verify the dict passed to Gate.evaluate() has the right shape."""
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("allow", "OK", "read_only")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = self._make_tool_call_msg("read_file", {"path": "/tmp/x"})
        proxy._handle_tool_call(msg)

        call_args = gate.evaluate.call_args[0][0]
        self.assertEqual(call_args["tool"], "read_file")
        self.assertEqual(call_args["input"], {"path": "/tmp/x"})

    def test_non_tool_call_not_intercepted(self):
        """Non-tool-call messages should not be handled."""
        msg = parse_message({
            "jsonrpc": "2.0", "id": 1,
            "method": "ping",
        })
        self.assertFalse(msg.is_tool_call)
        self.assertIsNone(msg.to_gate_format())


class TestAuditIntegration(unittest.TestCase):
    """Test that proxy logs to audit correctly."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_allow_is_audited(self):
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("allow", "OK", "read_only")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = parse_message({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
        })
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        audit_path = os.path.join(self.tmpdir, "audit.jsonl")
        with open(audit_path) as f:
            records = [json.loads(line) for line in f]
        self.assertTrue(len(records) >= 1)
        self.assertEqual(records[0]["tool_name"], "read_file")
        self.assertEqual(records[0]["verdict"], "allow")

    def test_deny_is_audited(self):
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("deny", "Blocked", "blocked")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = parse_message({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "rm", "arguments": {"path": "/"}},
        })
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        audit_path = os.path.join(self.tmpdir, "audit.jsonl")
        with open(audit_path) as f:
            records = [json.loads(line) for line in f]
        tool_records = [r for r in records if r["tool_name"] == "rm"]
        self.assertEqual(len(tool_records), 1)
        self.assertEqual(tool_records[0]["verdict"], "deny")

    def test_duration_is_recorded(self):
        gate = MagicMock()
        gate.evaluate.return_value = MockDecision("allow", "OK", "read_only")

        proxy = _make_proxy_with_mock_gate(gate, self.tmpdir)
        msg = parse_message({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "read", "arguments": {}},
        })
        proxy._handle_tool_call(msg)
        proxy.audit.close()

        audit_path = os.path.join(self.tmpdir, "audit.jsonl")
        with open(audit_path) as f:
            record = json.loads(f.readline())
        self.assertIn("duration_ms", record)
        self.assertIsInstance(record["duration_ms"], (int, float))


class TestServerProcess(unittest.TestCase):
    """Test MCP server subprocess management."""

    def test_start_and_stop_echo(self):
        """Launch a simple command, verify it starts and stops."""
        server = ServerProcess(["cat"])  # cat echoes stdin to stdout
        server.start()
        self.assertTrue(server.is_running)
        server.stop()
        self.assertFalse(server.is_running)

    def test_context_manager(self):
        """Context manager starts and stops cleanly."""
        with ServerProcess(["cat"]) as server:
            self.assertTrue(server.is_running)
        # After context exit, should be stopped
        self.assertFalse(server.is_running)

    def test_nonexistent_command_raises(self):
        """Non-existent command raises FileNotFoundError."""
        server = ServerProcess(["nonexistent_command_12345"])
        with self.assertRaises(FileNotFoundError):
            server.start()

    def test_server_has_stdio(self):
        """Server process provides stdin/stdout."""
        with ServerProcess(["cat"]) as server:
            self.assertIsNotNone(server.stdin)
            self.assertIsNotNone(server.stdout)


class TestServerNameInference(unittest.TestCase):
    """Test server name auto-detection from command."""

    def test_infer_from_server_prefix(self):
        proxy = MCPProxy(
            server_command=["npx", "@modelcontextprotocol/server-filesystem", "/path"],
            config=ProxyConfig(policy="/tmp/test.yaml"),
        )
        self.assertIn("server-filesystem", proxy.server_name)

    def test_infer_from_mcp_prefix(self):
        proxy = MCPProxy(
            server_command=["python", "-m", "mcp-server-sqlite"],
            config=ProxyConfig(policy="/tmp/test.yaml"),
        )
        self.assertIn("mcp-server-sqlite", proxy.server_name)

    def test_fallback_to_command_name(self):
        proxy = MCPProxy(
            server_command=["my-custom-tool"],
            config=ProxyConfig(policy="/tmp/test.yaml"),
        )
        self.assertEqual(proxy.server_name, "my-custom-tool")

    def test_explicit_name_overrides(self):
        proxy = MCPProxy(
            server_command=["npx", "server-filesystem"],
            config=ProxyConfig(policy="/tmp/test.yaml"),
            server_name="my-fs-server",
        )
        self.assertEqual(proxy.server_name, "my-fs-server")


class TestToolListFiltering(unittest.TestCase):
    """Test tools/list response handling."""

    def test_passthrough_by_default(self):
        """Without OPA filter_tools_list, responses pass through."""
        proxy = MCPProxy(
            server_command=["echo"],
            config=ProxyConfig(policy="/tmp/test.yaml"),
        )
        msg = parse_message({
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "read_file"}, {"name": "write_file"}]},
        })
        result = proxy._handle_tool_list_response(msg)
        self.assertIsNone(result)  # None = no modification


if __name__ == "__main__":
    unittest.main()
