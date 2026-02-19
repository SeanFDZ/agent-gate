"""
Agent Gate — MCP JSON-RPC Message Handling

Reads, writes, and classifies JSON-RPC 2.0 messages for MCP
stdio transport.

MCP stdio transport rules:
  - Messages are newline-delimited JSON-RPC 2.0
  - No embedded newlines in messages
  - stdin: client → server messages
  - stdout: server → client messages
  - stderr: logging only (never protocol messages)

This module is transport-agnostic in its parsing — the same
message types and classification work for HTTP+SSE when we
add that transport later.
"""

import json
import sys
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Any, TextIO, BinaryIO, Union


class MessageType(Enum):
    """JSON-RPC 2.0 message types."""
    REQUEST = "request"          # Has method + id
    RESPONSE = "response"        # Has result or error + id
    NOTIFICATION = "notification"  # Has method, no id


class MCPMethod(Enum):
    """
    MCP protocol methods we care about.

    The proxy needs to identify these to decide what to intercept
    vs. what to pass through.
    """
    # Lifecycle
    INITIALIZE = "initialize"
    INITIALIZED = "notifications/initialized"

    # Tools — the interception targets
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    TOOLS_LIST_CHANGED = "notifications/tools/list_changed"

    # Resources — pass through
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    RESOURCES_SUBSCRIBE = "resources/subscribe"
    RESOURCES_UNSUBSCRIBE = "resources/unsubscribe"

    # Prompts — pass through
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"

    # Logging
    LOGGING_SET_LEVEL = "logging/setLevel"

    # Completion
    COMPLETION = "completion/complete"

    # Ping
    PING = "ping"

    # Cancellation
    CANCELLED = "notifications/cancelled"

    # Progress
    PROGRESS = "notifications/progress"

    # Unknown — anything not in this enum
    UNKNOWN = "__unknown__"


@dataclass
class MCPMessage:
    """
    A parsed MCP JSON-RPC message.

    Attributes:
        raw: The original dict as parsed from JSON
        msg_type: Whether this is a request, response, or notification
        method: The MCP method (for requests/notifications)
        msg_id: The JSON-RPC id (for requests/responses)
        params: The params dict (for requests/notifications)
        result: The result dict (for successful responses)
        error: The error dict (for error responses)
    """
    raw: dict
    msg_type: MessageType
    method: Optional[MCPMethod] = None
    method_str: Optional[str] = None  # Original method string
    msg_id: Optional[Any] = None
    params: Optional[dict] = None
    result: Optional[Any] = None
    error: Optional[dict] = None

    @property
    def is_tool_call(self) -> bool:
        """Is this a tools/call request?"""
        return self.method == MCPMethod.TOOLS_CALL

    @property
    def is_tool_list(self) -> bool:
        """Is this a tools/list request?"""
        return self.method == MCPMethod.TOOLS_LIST

    @property
    def is_lifecycle(self) -> bool:
        """Is this an initialize or initialized message?"""
        return self.method in (MCPMethod.INITIALIZE, MCPMethod.INITIALIZED)

    @property
    def tool_name(self) -> Optional[str]:
        """Extract tool name from a tools/call request."""
        if not self.is_tool_call or not self.params:
            return None
        return self.params.get("name")

    @property
    def tool_arguments(self) -> Optional[dict]:
        """Extract tool arguments from a tools/call request."""
        if not self.is_tool_call or not self.params:
            return None
        return self.params.get("arguments", {})

    def to_gate_format(self) -> Optional[dict]:
        """
        Translate an MCP tools/call into Agent Gate's evaluation format.

        MCP tools/call:
            {"name": "read_file", "arguments": {"path": "/etc/hosts"}}

        Agent Gate format:
            {"tool": "read_file", "input": {"path": "/etc/hosts"}}

        Returns None if this isn't a tools/call message.
        """
        if not self.is_tool_call:
            return None
        return {
            "tool": self.tool_name,
            "input": self.tool_arguments or {},
        }


class ParseError(Exception):
    """Raised when a message cannot be parsed as valid JSON-RPC."""
    pass


def classify_message(raw: dict) -> MessageType:
    """
    Classify a JSON-RPC message by its structure.

    JSON-RPC 2.0 rules:
      - Request: has "method" and "id"
      - Notification: has "method" but no "id"
      - Response: has "result" or "error" and "id"
    """
    has_method = "method" in raw
    has_id = "id" in raw
    has_result = "result" in raw
    has_error = "error" in raw

    if has_method and has_id:
        return MessageType.REQUEST
    elif has_method and not has_id:
        return MessageType.NOTIFICATION
    elif has_id and (has_result or has_error):
        return MessageType.RESPONSE
    else:
        # Best guess — treat as request if it has a method
        if has_method:
            return MessageType.NOTIFICATION
        return MessageType.RESPONSE


def resolve_method(method_str: str) -> MCPMethod:
    """Map a method string to an MCPMethod enum value."""
    for member in MCPMethod:
        if member.value == method_str:
            return member
    return MCPMethod.UNKNOWN


def parse_message(data: Union[str, bytes, dict]) -> MCPMessage:
    """
    Parse a JSON-RPC message from raw input.

    Accepts:
      - A JSON string (as received from stdio)
      - Bytes (as received from a stream)
      - A dict (already parsed)

    Returns an MCPMessage with all fields populated.

    Raises ParseError if the input is not valid JSON-RPC.
    """
    # Step 1: Get to a dict
    if isinstance(data, bytes):
        data = data.decode("utf-8")

    if isinstance(data, str):
        data = data.strip()
        if not data:
            raise ParseError("Empty message")
        try:
            raw = json.loads(data)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON: {e}")
    elif isinstance(data, dict):
        raw = data
    else:
        raise ParseError(f"Unexpected input type: {type(data)}")

    # Step 2: Validate JSON-RPC structure
    if not isinstance(raw, dict):
        raise ParseError(f"Message must be a JSON object, got {type(raw)}")

    jsonrpc = raw.get("jsonrpc")
    if jsonrpc != "2.0":
        raise ParseError(
            f"Expected jsonrpc '2.0', got '{jsonrpc}'"
        )

    # Step 3: Classify and extract fields
    msg_type = classify_message(raw)
    method_str = raw.get("method")
    method = resolve_method(method_str) if method_str else None

    return MCPMessage(
        raw=raw,
        msg_type=msg_type,
        method=method,
        method_str=method_str,
        msg_id=raw.get("id"),
        params=raw.get("params"),
        result=raw.get("result"),
        error=raw.get("error"),
    )


def serialize_message(msg: dict) -> str:
    """
    Serialize a JSON-RPC message for stdio transport.

    Returns a JSON string with no embedded newlines, terminated
    by a single newline (MCP stdio framing).
    """
    # ensure_ascii=False for UTF-8 support, separators for compact output
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n"


def make_response(msg_id: Any, result: Any) -> dict:
    """Build a JSON-RPC success response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": result,
    }


def make_error_response(
    msg_id: Any,
    code: int,
    message: str,
    data: Optional[dict] = None,
) -> dict:
    """
    Build a JSON-RPC error response.

    Standard JSON-RPC error codes:
      -32700: Parse error
      -32600: Invalid request
      -32601: Method not found
      -32602: Invalid params
      -32603: Internal error

    Agent Gate uses custom codes in the -32000 range:
      -32001: Action denied by policy
      -32002: Action requires escalation
      -32003: Vault backup failed
    """
    error = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": error,
    }


# Agent Gate custom JSON-RPC error codes
GATE_DENIED = -32001
GATE_ESCALATE = -32002
GATE_VAULT_FAILED = -32003


def make_gate_denial(
    msg_id: Any,
    reason: str,
    tier: str,
    escalation_path: Optional[str] = None,
) -> dict:
    """
    Build a denial response from an Agent Gate verdict.

    This is what the MCP client receives when a tool call is
    blocked by policy. It follows JSON-RPC error format so the
    client can handle it like any other error, but includes
    Agent Gate metadata in the data field.
    """
    data = {
        "gate_verdict": "deny",
        "tier": tier,
        "reason": reason,
    }
    if escalation_path:
        data["escalation_path"] = escalation_path

    return make_error_response(
        msg_id=msg_id,
        code=GATE_DENIED,
        message=f"Agent Gate: action denied — {reason}",
        data=data,
    )


def make_gate_escalation(
    msg_id: Any,
    reason: str,
    tier: str,
    required_authority: Optional[str] = None,
) -> dict:
    """
    Build an escalation response from an Agent Gate verdict.

    The tool call isn't denied outright — it requires elevated
    authority or human approval to proceed.
    """
    data = {
        "gate_verdict": "escalate",
        "tier": tier,
        "reason": reason,
    }
    if required_authority:
        data["required_authority"] = required_authority

    return make_error_response(
        msg_id=msg_id,
        code=GATE_ESCALATE,
        message=f"Agent Gate: action requires escalation — {reason}",
        data=data,
    )


class StdioTransport:
    """
    Reads and writes newline-delimited JSON-RPC over stdio streams.

    This handles the raw I/O — reading lines from an input stream
    and writing serialized messages to an output stream. The proxy
    creates two of these: one for client communication and one for
    the real MCP server subprocess.
    """

    def __init__(
        self,
        reader: TextIO,
        writer: TextIO,
        name: str = "stdio",
    ):
        """
        Args:
            reader: Input stream to read messages from
            writer: Output stream to write messages to
            name: Label for logging (e.g., "client", "server")
        """
        self.reader = reader
        self.writer = writer
        self.name = name

    def read_message(self) -> Optional[MCPMessage]:
        """
        Read and parse the next JSON-RPC message from the input stream.

        Returns None on EOF (stream closed).
        Raises ParseError on invalid messages.
        """
        try:
            line = self.reader.readline()
        except (IOError, OSError) as e:
            return None

        if not line:
            return None  # EOF

        return parse_message(line)

    def write_message(self, msg: dict) -> None:
        """
        Serialize and write a JSON-RPC message to the output stream.
        """
        serialized = serialize_message(msg)
        try:
            self.writer.write(serialized)
            self.writer.flush()
        except (IOError, OSError, BrokenPipeError):
            pass  # Stream closed — handled by caller

    def write_raw(self, line: str) -> None:
        """
        Write a pre-serialized message line to the output stream.

        Used for passthrough — when we don't need to modify the
        message, we avoid the serialize/deserialize round-trip.
        """
        try:
            if not line.endswith("\n"):
                line = line + "\n"
            self.writer.write(line)
            self.writer.flush()
        except (IOError, OSError, BrokenPipeError):
            pass
