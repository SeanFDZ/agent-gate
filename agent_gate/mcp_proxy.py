"""
Agent Gate — MCP Proxy

A transparent MCP proxy that sits between any MCP client and server,
intercepting tools/call requests and routing them through
Gate.evaluate() before forwarding to the real server.

Architecture:
    LLM Client (Claude, etc.)
        │
        │  MCP JSON-RPC (stdio)
        ▼
    ┌──────────────┐
    │  AGENT GATE  │
    │  MCP PROXY   │
    ├──────────────┤
    │ Intercept    │ ← receive tools/call from client
    │ Translate    │ ← map to Gate.evaluate() format
    │ Gate         │ ← classify, envelope, vault, decide
    │ Route        │ ← ALLOW → forward to real server
    │              │   DENY → return error response to client
    │              │   ESCALATE → hold for human approval
    └──────────────┘
        │
        │  MCP JSON-RPC (stdio)
        ▼
    Real MCP Server (filesystem, database, API, etc.)

The proxy is transparent to both sides:
  - The client thinks it's talking to the MCP server
  - The server thinks it's talking to the MCP client
  - Neither knows the gate is there

Usage:
    # As CLI (wraps a real MCP server)
    python -m agent_gate.mcp_proxy -- npx @modelcontextprotocol/server-filesystem /path

    # With explicit policy
    AGENT_GATE_POLICY=./policies/default.yaml \\
    python -m agent_gate.mcp_proxy -- npx @modelcontextprotocol/server-filesystem /path
"""

import json
import os
import signal
import subprocess
import sys
import time
import uuid
import threading
import logging
from typing import Optional, List

from agent_gate.mcp_jsonrpc import (
    MCPMessage,
    MCPMethod,
    MessageType,
    ParseError,
    StdioTransport,
    make_gate_denial,
    make_gate_escalation,
    make_error_response,
    make_response,
    parse_message,
    serialize_message,
)
from agent_gate.proxy_config import ProxyConfig, build_config
from agent_gate.audit import AuditLogger

# Import Gate — the core evaluation engine
from agent_gate.gate import Gate, Verdict


def _log(msg: str) -> None:
    """Log to stderr (never stdout — that's the MCP channel)."""
    print(f"[agent-gate-proxy] {msg}", file=sys.stderr, flush=True)


class ServerProcess:
    """
    Manages the real MCP server as a subprocess.

    Launches the server command, connects stdin/stdout pipes,
    and handles lifecycle (start, health, shutdown).
    """

    def __init__(self, command: List[str], env: Optional[dict] = None):
        """
        Args:
            command: The server command and arguments
                     e.g., ["npx", "@modelcontextprotocol/server-filesystem", "/path"]
            env: Optional environment variables for the subprocess.
                 If None, inherits the parent process environment.
        """
        self.command = command
        self.env = env or dict(os.environ)
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> None:
        """Launch the MCP server subprocess."""
        _log(f"Starting MCP server: {' '.join(self.command)}")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,  # Server logs go to our stderr
                env=self.env,
                bufsize=0,  # Unbuffered for real-time message passing
            )
        except FileNotFoundError:
            _log(f"ERROR: Command not found: {self.command[0]}")
            raise
        except Exception as e:
            _log(f"ERROR: Failed to start server: {e}")
            raise

        _log(f"MCP server started (PID {self.process.pid})")

    @property
    def stdin(self):
        """Server's stdin (we write to this)."""
        return self.process.stdin if self.process else None

    @property
    def stdout(self):
        """Server's stdout (we read from this)."""
        return self.process.stdout if self.process else None

    @property
    def is_running(self) -> bool:
        """Check if the server process is still alive."""
        if not self.process:
            return False
        return self.process.poll() is None

    def stop(self) -> None:
        """Gracefully stop the server subprocess."""
        if not self.process:
            return

        _log("Stopping MCP server...")

        # Close stdin to signal the server to exit
        if self.process.stdin and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except Exception:
                pass

        # Wait briefly for clean exit
        try:
            self.process.wait(timeout=5)
            _log(f"MCP server exited (code {self.process.returncode})")
        except subprocess.TimeoutExpired:
            _log("MCP server didn't exit cleanly, sending SIGTERM")
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _log("MCP server still running, sending SIGKILL")
                self.process.kill()
                self.process.wait()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


class MCPProxy:
    """
    The core MCP proxy — intercepts, evaluates, and routes messages.

    This is the main class that ties everything together:
      - Reads messages from the client (our stdin)
      - For tools/call: translates to Gate format, evaluates, routes
      - For everything else: passes through to the server
      - Reads responses from the server and forwards to the client
    """

    def __init__(
        self,
        server_command: List[str],
        config: Optional[ProxyConfig] = None,
        server_name: Optional[str] = None,
    ):
        """
        Args:
            server_command: Command to launch the real MCP server
            config: Proxy configuration (auto-loaded if None)
            server_name: Human-readable name for the server (for audit logs)
        """
        self.server_command = server_command
        self.config = config or build_config()
        self.server_name = server_name or self._infer_server_name()
        self.session_id = str(uuid.uuid4())[:8]
        self.gate: Optional[Gate] = None
        self.server: Optional[ServerProcess] = None
        self.audit: Optional[AuditLogger] = None
        self._running = False

    def _infer_server_name(self) -> str:
        """Guess a server name from the command."""
        for part in self.server_command:
            if "server-" in part or "mcp-" in part:
                return part.split("/")[-1]
        return self.server_command[0] if self.server_command else "unknown"

    def _init_gate(self) -> bool:
        """
        Initialize the Gate evaluation engine.

        Returns True if successful, False if config is invalid.
        """
        errors = self.config.validate()
        if errors:
            for err in errors:
                _log(f"Config error: {err}")
            return False

        try:
            kwargs = self.config.to_gate_kwargs()
            self.gate = Gate(**kwargs)
            _log(f"Gate initialized (backend={self.config.classifier_backend})")
            return True
        except Exception as e:
            _log(f"Failed to initialize gate: {e}")
            return False

    def _init_audit(self) -> None:
        """Initialize the audit logger."""
        self.audit = AuditLogger(
            path=self.config.audit_log,
            server_name=self.server_name,
            session_id=self.session_id,
        )
        self.audit.log_proxy_event("proxy_started", {
            "server_command": " ".join(self.server_command),
            "config_source": self.config.config_source,
            "classifier_backend": self.config.classifier_backend,
        })

    def _handle_tool_call(self, msg: MCPMessage) -> Optional[dict]:
        """
        Intercept a tools/call request and evaluate it through the Gate.

        Returns:
          - None if the call is ALLOWED (forward to server)
          - A JSON-RPC error response dict if DENIED or ESCALATED
        """
        gate_input = msg.to_gate_format()
        if not gate_input or not self.gate:
            return None

        tool_name = gate_input["tool"]
        tool_input = gate_input["input"]

        _log(f"Evaluating: {tool_name} {json.dumps(tool_input)[:100]}")

        start_time = time.time()

        try:
            decision = self.gate.evaluate(gate_input)
        except Exception as e:
            _log(f"Gate evaluation error: {e}")
            # On gate error, deny for safety (fail closed)
            if self.audit:
                self.audit.log_tool_call(
                    tool_name=tool_name,
                    arguments=tool_input,
                    verdict="deny",
                    tier="error",
                    reason=f"Gate evaluation error: {e}",
                    msg_id=msg.msg_id,
                )
            return make_error_response(
                msg.msg_id, -32603,
                f"Agent Gate: internal error during evaluation",
            )

        duration_ms = (time.time() - start_time) * 1000

        # Audit the decision
        if self.audit:
            vault_path = None
            if hasattr(decision, 'vault_result') and decision.vault_result:
                vault_path = getattr(decision.vault_result, 'backup_path', None)

            self.audit.log_tool_call(
                tool_name=tool_name,
                arguments=tool_input,
                verdict=decision.verdict.value,
                tier=decision.classification.tier.value if decision.classification else "unknown",
                reason=decision.reason,
                msg_id=msg.msg_id,
                vault_path=vault_path,
                duration_ms=round(duration_ms, 2),
            )

        # Route based on verdict
        if decision.verdict == Verdict.ALLOW:
            _log(f"ALLOW: {tool_name} ({round(duration_ms, 1)}ms)")
            return None  # Forward to server

        elif decision.verdict == Verdict.DENY:
            _log(f"DENY: {tool_name} — {decision.reason}")
            tier = decision.classification.tier.value if decision.classification else "unknown"
            return make_gate_denial(
                msg_id=msg.msg_id,
                reason=decision.reason,
                tier=tier,
                escalation_path=getattr(decision, 'escalation_path', None),
            )

        elif decision.verdict == Verdict.ESCALATE:
            _log(f"ESCALATE: {tool_name} — {decision.reason}")
            tier = decision.classification.tier.value if decision.classification else "unknown"
            return make_gate_escalation(
                msg_id=msg.msg_id,
                reason=decision.reason,
                tier=tier,
            )

        # Shouldn't reach here, but fail closed
        return make_error_response(
            msg.msg_id, -32603,
            "Agent Gate: unexpected verdict",
        )

    def _handle_tool_list_response(self, msg: MCPMessage) -> Optional[dict]:
        """
        Optionally filter tools/list responses (OPA only).

        For the default Python backend, this returns None (no modification).
        For OPA with filter_tools_list=True, this queries OPA to filter
        the tool list by role/principal entitlements.
        """
        if not self.config.opa.filter_tools_list:
            return None  # Passthrough

        # OPA tool filtering — Phase 3 stretch goal
        # For now, passthrough even with the flag set
        _log("tools/list filtering requested but not yet implemented")
        return None

    def _forward_to_server(
        self,
        server_transport: StdioTransport,
        msg: MCPMessage,
    ) -> None:
        """Forward a message to the real MCP server."""
        server_transport.write_message(msg.raw)

    def _forward_to_client(
        self,
        client_transport: StdioTransport,
        msg: dict,
    ) -> None:
        """Send a message (response or forwarded) to the client."""
        client_transport.write_message(msg)

    def _server_reader_thread(
        self,
        server_transport: StdioTransport,
        client_transport: StdioTransport,
    ) -> None:
        """
        Background thread: reads from the server and forwards to client.

        This runs in a separate thread because both the client and
        server can send messages at any time (the server sends
        responses to our forwarded requests, plus notifications).
        """
        while self._running:
            try:
                msg = server_transport.read_message()
            except ParseError as e:
                _log(f"Server parse error: {e}")
                continue
            except Exception:
                break

            if msg is None:
                _log("Server connection closed")
                self._running = False
                break

            # Check if this is a tools/list response we should filter
            if (msg.msg_type == MessageType.RESPONSE
                    and msg.result is not None
                    and isinstance(msg.result, dict)
                    and "tools" in msg.result):
                filtered = self._handle_tool_list_response(msg)
                if filtered:
                    client_transport.write_message(filtered)
                    continue

            # Forward server message to client as-is
            client_transport.write_message(msg.raw)

    def run(self) -> int:
        """
        Main proxy loop.

        Returns exit code (0 for clean shutdown).
        """
        # Initialize Gate
        if not self._init_gate():
            _log("Failed to initialize. Check configuration.")
            return 1

        # Initialize audit
        self._init_audit()

        # Start the real MCP server
        self.server = ServerProcess(self.server_command)
        try:
            self.server.start()
        except Exception as e:
            _log(f"Failed to start MCP server: {e}")
            return 1

        if not self.server.stdout or not self.server.stdin:
            _log("Server process has no stdio — cannot proxy")
            self.server.stop()
            return 1

        # Create transports
        # Client transport: reads from our stdin, writes to our stdout
        client_in = sys.stdin
        client_out = sys.stdout

        # Server transport: reads from server stdout, writes to server stdin
        # We need text wrappers around the binary pipes
        server_stdout_text = os.fdopen(
            os.dup(self.server.stdout.fileno()), "r", encoding="utf-8"
        )
        server_stdin_text = os.fdopen(
            os.dup(self.server.stdin.fileno()), "w", encoding="utf-8"
        )

        client_transport = StdioTransport(client_in, client_out, "client")
        server_transport = StdioTransport(
            server_stdout_text, server_stdin_text, "server"
        )

        # Start background thread for server → client messages
        self._running = True
        reader_thread = threading.Thread(
            target=self._server_reader_thread,
            args=(server_transport, client_transport),
            daemon=True,
        )
        reader_thread.start()

        _log(f"Proxy ready (session={self.session_id}, server={self.server_name})")

        # Main loop: read from client, intercept or forward
        try:
            while self._running:
                try:
                    msg = client_transport.read_message()
                except ParseError as e:
                    _log(f"Client parse error: {e}")
                    continue
                except Exception:
                    break

                if msg is None:
                    _log("Client connection closed")
                    break

                # Intercept tools/call
                if msg.is_tool_call:
                    denial = self._handle_tool_call(msg)
                    if denial:
                        # Denied or escalated — send error back to client
                        client_transport.write_message(denial)
                        continue
                    # Allowed — fall through to forward

                # Forward everything else to the real server
                self._forward_to_server(server_transport, msg)

        except KeyboardInterrupt:
            _log("Interrupted")
        finally:
            self._running = False

            if self.audit:
                self.audit.log_proxy_event("proxy_stopped")
                self.audit.close()

            # Clean up server
            self.server.stop()

            # Close our duplicated file descriptors
            try:
                server_stdout_text.close()
            except Exception:
                pass
            try:
                server_stdin_text.close()
            except Exception:
                pass

        _log("Proxy shutdown complete")
        return 0


def main():
    """CLI entry point for the MCP proxy."""
    args = sys.argv[1:]

    # Split on -- to separate proxy args from server command
    if "--" in args:
        split_idx = args.index("--")
        proxy_args = args[:split_idx]
        server_command = args[split_idx + 1:]
    else:
        proxy_args = []
        server_command = args

    if not server_command:
        print(
            "Usage: python -m agent_gate.mcp_proxy [options] -- <server_command> [server_args...]\n"
            "\n"
            "Example:\n"
            "  python -m agent_gate.mcp_proxy -- npx @modelcontextprotocol/server-filesystem /path\n"
            "\n"
            "Environment variables:\n"
            "  AGENT_GATE_POLICY    Path to policy YAML file\n"
            "  AGENT_GATE_WORKDIR   Working directory for path resolution\n"
            "  AGENT_GATE_BACKEND   Classifier backend: 'python' (default) or 'opa'\n"
            "  AGENT_GATE_AUDIT_LOG Path to audit log file\n"
            "\n"
            "Config file: ~/.config/agent-gate/proxy.yaml\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # Parse proxy-specific args
    config_path = None
    server_name = None

    i = 0
    while i < len(proxy_args):
        if proxy_args[i] in ("--config", "-c") and i + 1 < len(proxy_args):
            config_path = proxy_args[i + 1]
            i += 2
        elif proxy_args[i] in ("--name", "-n") and i + 1 < len(proxy_args):
            server_name = proxy_args[i + 1]
            i += 2
        else:
            _log(f"Unknown option: {proxy_args[i]}")
            i += 1

    # Build config
    config = build_config(config_path=config_path)

    # Create and run proxy
    proxy = MCPProxy(
        server_command=server_command,
        config=config,
        server_name=server_name,
    )

    sys.exit(proxy.run())


if __name__ == "__main__":
    main()
