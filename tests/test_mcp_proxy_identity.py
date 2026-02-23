"""
Tests for MCP Proxy identity resolution and propagation (Phase 6.6).

Tests cover:
  - Identity resolution from environment variables
  - Session ID consistency between proxy and identity
  - Anonymous identity when no env vars set
  - Gate initialization receives identity
  - Audit startup event includes identity
  - Audit tool call includes identity fields
  - Policy YAML identity config reading
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.mcp_proxy import MCPProxy
from agent_gate.proxy_config import ProxyConfig
from agent_gate.audit import AuditLogger
from agent_gate.mcp_jsonrpc import parse_message, GATE_DENIED


# --- Helpers ---

IDENTITY_POLICY_PATH = os.path.join(
    os.path.dirname(__file__), "test_fixtures", "policy_with_identity.yaml"
)


def _make_config(tmpdir, policy_path=None):
    """Build a ProxyConfig pointing at a test policy."""
    return ProxyConfig(
        policy=policy_path or IDENTITY_POLICY_PATH,
        workdir=tmpdir,
        audit_log=os.path.join(tmpdir, "audit.jsonl"),
    )


class MockTier:
    def __init__(self, value):
        self.value = value


class MockClassification:
    def __init__(self, tier_value="read_only"):
        self.tier = MockTier(tier_value)


class MockDecision:
    """Mimics GateDecision for proxy tests."""
    def __init__(self, verdict_str, reason, tier_value="read_only"):
        self.verdict = MagicMock()
        self.verdict.value = verdict_str
        from agent_gate.gate import Verdict
        if verdict_str == "allow":
            self.verdict.__eq__ = lambda s, other: other == Verdict.ALLOW
        elif verdict_str == "deny":
            self.verdict.__eq__ = lambda s, other: other == Verdict.DENY
        self.reason = reason
        self.classification = MockClassification(tier_value)
        self.vault_result = None


# --- Identity Resolution ---

class TestProxyIdentityResolution(unittest.TestCase):
    """Test that MCPProxy resolves identity from environment."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch.dict(os.environ, {
        "AGENT_GATE_OPERATOR": "sean",
        "AGENT_GATE_ROLE": "admin",
    }, clear=False)
    def test_proxy_resolves_identity_from_env(self):
        """Proxy picks up AGENT_GATE_OPERATOR and AGENT_GATE_ROLE."""
        config = _make_config(self.tmpdir)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
            server_name="test-server",
        )
        self.assertEqual(proxy.identity.operator, "sean")
        self.assertEqual(proxy.identity.role, "admin")

    def test_proxy_identity_includes_session_id(self):
        """Proxy session_id flows into identity.session_id."""
        config = _make_config(self.tmpdir)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
        )
        self.assertEqual(proxy.identity.session_id, proxy.session_id)

    @patch.dict(os.environ, {}, clear=True)
    def test_proxy_no_identity_env_anonymous(self):
        """Without AGENT_GATE_* env vars, identity is anonymous."""
        # Restore minimal env for subprocess/yaml imports
        env_restore = {
            "HOME": os.path.expanduser("~"),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
        with patch.dict(os.environ, env_restore, clear=True):
            config = _make_config(self.tmpdir)
            proxy = MCPProxy(
                server_command=["echo", "test"],
                config=config,
            )
            self.assertIsNone(proxy.identity.operator)
            self.assertFalse(proxy.identity.has_identity())
            # Still has a session_id
            self.assertIsNotNone(proxy.identity.session_id)


# --- Gate Initialization ---

class TestProxyGateIdentity(unittest.TestCase):
    """Test that _init_gate passes identity to Gate."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch.dict(os.environ, {"AGENT_GATE_ROLE": "admin"}, clear=False)
    def test_init_gate_receives_identity(self):
        """Gate receives the proxy's identity context."""
        config = _make_config(self.tmpdir)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
        )
        result = proxy._init_gate()
        self.assertTrue(result)
        self.assertIsNotNone(proxy.gate)
        self.assertIsNotNone(proxy.gate.identity)
        self.assertEqual(proxy.gate.identity.role, "admin")

    def test_init_gate_no_identity_works(self):
        """Gate initializes with anonymous identity (no crash)."""
        config = _make_config(self.tmpdir)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
        )
        result = proxy._init_gate()
        self.assertTrue(result)
        self.assertIsNotNone(proxy.gate.identity)
        # Has session_id even without named identity
        self.assertIsNotNone(proxy.gate.identity.session_id)


# --- Audit Integration ---

class TestProxyAuditIdentity(unittest.TestCase):
    """Test that audit records include identity."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch.dict(os.environ, {
        "AGENT_GATE_OPERATOR": "sean",
        "AGENT_GATE_ROLE": "admin",
    }, clear=False)
    def test_audit_startup_includes_identity(self):
        """proxy_started event contains identity dict."""
        config = _make_config(self.tmpdir)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
            server_name="test-server",
        )
        proxy._init_audit()
        proxy.audit.close()

        audit_path = os.path.join(self.tmpdir, "audit.jsonl")
        with open(audit_path) as f:
            records = [json.loads(line) for line in f]

        startup = [r for r in records if r["reason"] == "proxy_started"]
        self.assertEqual(len(startup), 1)
        args = startup[0]["arguments"]
        self.assertIn("identity", args)
        self.assertEqual(args["identity"]["operator"], "sean")
        self.assertEqual(args["identity"]["role"], "admin")

    @patch.dict(os.environ, {
        "AGENT_GATE_OPERATOR": "sean",
        "AGENT_GATE_ROLE": "admin",
    }, clear=False)
    def test_audit_tool_call_includes_identity(self):
        """Tool call audit records include operator and role."""
        config = _make_config(self.tmpdir)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
            server_name="test-server",
        )
        # Init gate and audit
        proxy._init_gate()
        proxy._init_audit()

        # Mock gate.evaluate to return ALLOW
        gate_mock = MagicMock()
        gate_mock.evaluate.return_value = MockDecision("allow", "OK", "read_only")
        gate_mock.policy.policy_hash = "testhash"
        gate_mock.rate_tracker.get_rate_context.return_value = {}
        proxy.gate = gate_mock

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

        tool_records = [r for r in records if r["tool_name"] == "read_file"]
        self.assertEqual(len(tool_records), 1)
        self.assertEqual(tool_records[0]["operator"], "sean")
        self.assertEqual(tool_records[0]["role"], "admin")


# --- Config Read ---

class TestReadIdentityConfig(unittest.TestCase):
    """Test _read_identity_config reads identity.fields from YAML."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_identity_config_from_yaml(self):
        """Policy with identity section returns fields dict."""
        config = _make_config(self.tmpdir, IDENTITY_POLICY_PATH)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
        )
        fields = proxy._read_identity_config()
        self.assertIsNotNone(fields)
        self.assertIn("operator", fields)
        self.assertIn("role", fields)

    def test_read_identity_config_missing_section(self):
        """Policy without identity section returns None."""
        # Create a minimal policy without identity
        policy_path = os.path.join(self.tmpdir, "no_identity.yaml")
        with open(policy_path, "w") as f:
            f.write("""
gate:
  name: minimal
  description: no identity
envelope:
  allowed_paths:
    - /tmp
  denied_paths:
    - /tmp/.vault
vault:
  path: /tmp/.vault
  on_failure: deny
actions:
  destructive:
    patterns:
      - command: rm
  read_only:
    patterns:
      - command: cat
  blocked:
    patterns:
      - command: rm
        args_contain: ["-rf /"]
gate_behavior:
  on_unclassified:
    default: deny
""")
        config = _make_config(self.tmpdir, policy_path)
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
        )
        fields = proxy._read_identity_config()
        self.assertIsNone(fields)

    def test_read_identity_config_no_policy_file(self):
        """Non-existent policy file returns None (no crash)."""
        config = ProxyConfig(
            policy="/nonexistent/policy.yaml",
            workdir=self.tmpdir,
            audit_log=os.path.join(self.tmpdir, "audit.jsonl"),
        )
        proxy = MCPProxy(
            server_command=["echo", "test"],
            config=config,
        )
        fields = proxy._read_identity_config()
        self.assertIsNone(fields)


if __name__ == "__main__":
    unittest.main()
