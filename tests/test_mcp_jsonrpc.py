"""
Tests for Agent Gate MCP JSON-RPC message handling.

Tests cover:
  - Message parsing (string, bytes, dict input)
  - Message classification (request, response, notification)
  - MCP method resolution
  - tools/call extraction and Gate format translation
  - Serialization (no embedded newlines)
  - Error response builders
  - Gate denial/escalation response builders
  - StdioTransport read/write
"""

import json
import io
import sys
import os
import unittest

# PYTHONPATH-based import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.mcp_jsonrpc import (
    MCPMessage,
    MCPMethod,
    MessageType,
    ParseError,
    StdioTransport,
    classify_message,
    make_error_response,
    make_gate_denial,
    make_gate_escalation,
    make_response,
    parse_message,
    resolve_method,
    serialize_message,
    GATE_DENIED,
    GATE_ESCALATE,
    GATE_VAULT_FAILED,
)


class TestMessageClassification(unittest.TestCase):
    """Test JSON-RPC message type classification."""

    def test_request(self):
        """Request: has method + id."""
        raw = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}
        self.assertEqual(classify_message(raw), MessageType.REQUEST)

    def test_notification(self):
        """Notification: has method, no id."""
        raw = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertEqual(classify_message(raw), MessageType.NOTIFICATION)

    def test_success_response(self):
        """Response with result."""
        raw = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        self.assertEqual(classify_message(raw), MessageType.RESPONSE)

    def test_error_response(self):
        """Response with error."""
        raw = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Not found"}}
        self.assertEqual(classify_message(raw), MessageType.RESPONSE)

    def test_request_with_string_id(self):
        """Request with string id (JSON-RPC allows string or number)."""
        raw = {"jsonrpc": "2.0", "id": "abc-123", "method": "ping"}
        self.assertEqual(classify_message(raw), MessageType.REQUEST)


class TestMethodResolution(unittest.TestCase):
    """Test MCP method string → enum resolution."""

    def test_tools_call(self):
        self.assertEqual(resolve_method("tools/call"), MCPMethod.TOOLS_CALL)

    def test_tools_list(self):
        self.assertEqual(resolve_method("tools/list"), MCPMethod.TOOLS_LIST)

    def test_initialize(self):
        self.assertEqual(resolve_method("initialize"), MCPMethod.INITIALIZE)

    def test_initialized_notification(self):
        self.assertEqual(
            resolve_method("notifications/initialized"),
            MCPMethod.INITIALIZED,
        )

    def test_tools_list_changed(self):
        self.assertEqual(
            resolve_method("notifications/tools/list_changed"),
            MCPMethod.TOOLS_LIST_CHANGED,
        )

    def test_unknown_method(self):
        self.assertEqual(resolve_method("custom/something"), MCPMethod.UNKNOWN)

    def test_ping(self):
        self.assertEqual(resolve_method("ping"), MCPMethod.PING)

    def test_resources_list(self):
        self.assertEqual(resolve_method("resources/list"), MCPMethod.RESOURCES_LIST)


class TestParseMessage(unittest.TestCase):
    """Test message parsing from various input formats."""

    def test_parse_from_string(self):
        """Parse a JSON string."""
        raw = '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}'
        msg = parse_message(raw)
        self.assertEqual(msg.msg_type, MessageType.REQUEST)
        self.assertEqual(msg.method, MCPMethod.TOOLS_LIST)
        self.assertEqual(msg.msg_id, 1)

    def test_parse_from_bytes(self):
        """Parse bytes (as from a binary stream)."""
        raw = b'{"jsonrpc": "2.0", "id": 2, "method": "ping"}'
        msg = parse_message(raw)
        self.assertEqual(msg.msg_type, MessageType.REQUEST)
        self.assertEqual(msg.method, MCPMethod.PING)

    def test_parse_from_dict(self):
        """Parse an already-parsed dict."""
        raw = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "rm", "arguments": {"path": "/tmp/x"}}}
        msg = parse_message(raw)
        self.assertEqual(msg.msg_type, MessageType.REQUEST)
        self.assertEqual(msg.method, MCPMethod.TOOLS_CALL)

    def test_parse_strips_whitespace(self):
        """Handles leading/trailing whitespace and newlines."""
        raw = '  {"jsonrpc": "2.0", "id": 1, "method": "ping"}  \n'
        msg = parse_message(raw)
        self.assertEqual(msg.method, MCPMethod.PING)

    def test_parse_empty_string_raises(self):
        with self.assertRaises(ParseError):
            parse_message("")

    def test_parse_invalid_json_raises(self):
        with self.assertRaises(ParseError):
            parse_message("{not valid json}")

    def test_parse_wrong_jsonrpc_version_raises(self):
        with self.assertRaises(ParseError):
            parse_message('{"jsonrpc": "1.0", "id": 1, "method": "ping"}')

    def test_parse_missing_jsonrpc_raises(self):
        with self.assertRaises(ParseError):
            parse_message('{"id": 1, "method": "ping"}')

    def test_parse_non_object_raises(self):
        with self.assertRaises(ParseError):
            parse_message("[1, 2, 3]")

    def test_parse_response_message(self):
        """Parse a success response."""
        raw = {"jsonrpc": "2.0", "id": 5, "result": {"tools": [{"name": "read_file"}]}}
        msg = parse_message(raw)
        self.assertEqual(msg.msg_type, MessageType.RESPONSE)
        self.assertIsNone(msg.method)
        self.assertEqual(msg.msg_id, 5)
        self.assertIsNotNone(msg.result)

    def test_parse_error_response(self):
        """Parse an error response."""
        raw = {"jsonrpc": "2.0", "id": 6, "error": {"code": -32601, "message": "Method not found"}}
        msg = parse_message(raw)
        self.assertEqual(msg.msg_type, MessageType.RESPONSE)
        self.assertIsNotNone(msg.error)

    def test_parse_notification(self):
        """Parse a notification (no id)."""
        raw = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        msg = parse_message(raw)
        self.assertEqual(msg.msg_type, MessageType.NOTIFICATION)
        self.assertEqual(msg.method, MCPMethod.INITIALIZED)
        self.assertIsNone(msg.msg_id)


class TestToolCallExtraction(unittest.TestCase):
    """Test tools/call field extraction and Gate format translation."""

    def _make_tool_call(self, name, arguments=None):
        """Helper to build a tools/call message."""
        params = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        return parse_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": params,
        })

    def test_is_tool_call(self):
        msg = self._make_tool_call("read_file", {"path": "/etc/hosts"})
        self.assertTrue(msg.is_tool_call)
        self.assertFalse(msg.is_tool_list)

    def test_tool_name(self):
        msg = self._make_tool_call("write_file", {"path": "/tmp/x", "content": "hi"})
        self.assertEqual(msg.tool_name, "write_file")

    def test_tool_arguments(self):
        msg = self._make_tool_call("read_file", {"path": "/etc/hosts"})
        self.assertEqual(msg.tool_arguments, {"path": "/etc/hosts"})

    def test_tool_arguments_default_empty(self):
        """No arguments → empty dict."""
        msg = self._make_tool_call("list_tools")
        self.assertEqual(msg.tool_arguments, {})

    def test_to_gate_format(self):
        """MCP tools/call → Agent Gate evaluate format."""
        msg = self._make_tool_call("read_file", {"path": "/etc/hosts"})
        gate_format = msg.to_gate_format()
        self.assertEqual(gate_format, {
            "tool": "read_file",
            "input": {"path": "/etc/hosts"},
        })

    def test_to_gate_format_non_tool_call_returns_none(self):
        """Non-tool-call messages return None."""
        msg = parse_message({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertIsNone(msg.to_gate_format())

    def test_to_gate_format_complex_arguments(self):
        """Complex nested arguments translate cleanly."""
        args = {
            "query": "SELECT * FROM users WHERE role = 'admin'",
            "database": "production",
            "options": {"timeout": 30, "read_only": True},
        }
        msg = self._make_tool_call("database_query", args)
        gate_format = msg.to_gate_format()
        self.assertEqual(gate_format["tool"], "database_query")
        self.assertEqual(gate_format["input"], args)

    def test_is_tool_list(self):
        msg = parse_message({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/list", "params": {},
        })
        self.assertTrue(msg.is_tool_list)
        self.assertFalse(msg.is_tool_call)

    def test_is_lifecycle(self):
        msg = parse_message({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        })
        self.assertTrue(msg.is_lifecycle)


class TestSerialization(unittest.TestCase):
    """Test message serialization for stdio transport."""

    def test_serialize_no_embedded_newlines(self):
        """MCP requirement: no embedded newlines."""
        msg = {"jsonrpc": "2.0", "id": 1, "result": {"text": "line1\nline2"}}
        serialized = serialize_message(msg)
        # The newline in "text" should be escaped as \n in JSON
        lines = serialized.split("\n")
        # Should be exactly 2 parts: the message and the empty string after trailing \n
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "")

    def test_serialize_ends_with_newline(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        serialized = serialize_message(msg)
        self.assertTrue(serialized.endswith("\n"))

    def test_serialize_compact(self):
        """No unnecessary whitespace."""
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        serialized = serialize_message(msg)
        self.assertNotIn(" ", serialized.strip())

    def test_serialize_roundtrip(self):
        """Serialize → parse produces equivalent message."""
        original = {"jsonrpc": "2.0", "id": 42, "method": "tools/call", "params": {"name": "test", "arguments": {"a": 1}}}
        serialized = serialize_message(original)
        reparsed = parse_message(serialized)
        self.assertEqual(reparsed.msg_id, 42)
        self.assertEqual(reparsed.tool_name, "test")


class TestResponseBuilders(unittest.TestCase):
    """Test JSON-RPC response construction helpers."""

    def test_make_response(self):
        resp = make_response(1, {"tools": []})
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"], {"tools": []})
        self.assertNotIn("error", resp)

    def test_make_error_response(self):
        resp = make_error_response(2, -32601, "Method not found")
        self.assertEqual(resp["id"], 2)
        self.assertEqual(resp["error"]["code"], -32601)
        self.assertEqual(resp["error"]["message"], "Method not found")

    def test_make_error_response_with_data(self):
        resp = make_error_response(3, -32603, "Internal error", {"detail": "stack overflow"})
        self.assertEqual(resp["error"]["data"]["detail"], "stack overflow")

    def test_make_gate_denial(self):
        resp = make_gate_denial(
            msg_id=10,
            reason="rm -rf / blocked by policy",
            tier="blocked",
        )
        self.assertEqual(resp["error"]["code"], GATE_DENIED)
        self.assertEqual(resp["error"]["data"]["gate_verdict"], "deny")
        self.assertEqual(resp["error"]["data"]["tier"], "blocked")
        self.assertIn("rm -rf /", resp["error"]["message"])

    def test_make_gate_denial_with_escalation_path(self):
        resp = make_gate_denial(
            msg_id=11,
            reason="destructive action",
            tier="destructive",
            escalation_path="Requires admin approval",
        )
        self.assertEqual(
            resp["error"]["data"]["escalation_path"],
            "Requires admin approval",
        )

    def test_make_gate_escalation(self):
        resp = make_gate_escalation(
            msg_id=12,
            reason="network access requires review",
            tier="network",
            required_authority="security-team",
        )
        self.assertEqual(resp["error"]["code"], GATE_ESCALATE)
        self.assertEqual(resp["error"]["data"]["gate_verdict"], "escalate")
        self.assertEqual(resp["error"]["data"]["required_authority"], "security-team")


class TestStdioTransport(unittest.TestCase):
    """Test stdio transport read/write."""

    def test_read_message(self):
        """Read a single message from a stream."""
        line = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        reader = io.StringIO(line)
        writer = io.StringIO()
        transport = StdioTransport(reader, writer, name="test")

        msg = transport.read_message()
        self.assertIsNotNone(msg)
        self.assertEqual(msg.method, MCPMethod.PING)

    def test_read_multiple_messages(self):
        """Read multiple newline-delimited messages."""
        lines = (
            '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
        )
        reader = io.StringIO(lines)
        writer = io.StringIO()
        transport = StdioTransport(reader, writer, name="test")

        msg1 = transport.read_message()
        msg2 = transport.read_message()
        self.assertEqual(msg1.method, MCPMethod.PING)
        self.assertEqual(msg2.method, MCPMethod.TOOLS_LIST)

    def test_read_eof_returns_none(self):
        """EOF returns None."""
        reader = io.StringIO("")
        writer = io.StringIO()
        transport = StdioTransport(reader, writer, name="test")

        msg = transport.read_message()
        self.assertIsNone(msg)

    def test_write_message(self):
        """Write a message to the output stream."""
        reader = io.StringIO("")
        writer = io.StringIO()
        transport = StdioTransport(reader, writer, name="test")

        transport.write_message({"jsonrpc": "2.0", "id": 1, "result": "ok"})
        output = writer.getvalue()
        self.assertTrue(output.endswith("\n"))
        parsed = json.loads(output.strip())
        self.assertEqual(parsed["result"], "ok")

    def test_write_raw(self):
        """Write a pre-serialized line."""
        reader = io.StringIO("")
        writer = io.StringIO()
        transport = StdioTransport(reader, writer, name="test")

        transport.write_raw('{"jsonrpc":"2.0","id":1,"result":"ok"}')
        output = writer.getvalue()
        self.assertTrue(output.endswith("\n"))

    def test_write_raw_already_has_newline(self):
        """write_raw doesn't double-add newlines."""
        reader = io.StringIO("")
        writer = io.StringIO()
        transport = StdioTransport(reader, writer, name="test")

        transport.write_raw('{"jsonrpc":"2.0","id":1,"result":"ok"}\n')
        output = writer.getvalue()
        self.assertFalse(output.endswith("\n\n"))


class TestCustomErrorCodes(unittest.TestCase):
    """Verify Agent Gate custom error codes are distinct."""

    def test_codes_are_in_custom_range(self):
        """Custom codes should be in -32000 to -32099 range."""
        for code in [GATE_DENIED, GATE_ESCALATE, GATE_VAULT_FAILED]:
            self.assertGreaterEqual(code, -32099)
            self.assertLessEqual(code, -32000)

    def test_codes_are_unique(self):
        codes = [GATE_DENIED, GATE_ESCALATE, GATE_VAULT_FAILED]
        self.assertEqual(len(codes), len(set(codes)))


if __name__ == "__main__":
    unittest.main()
