# Phase 6.6: MCP Proxy — Identity Resolution & Propagation

**File:** `mcp_proxy.py`
**Depends on:** Phase 6.1 (identity.py), Phase 6.3 (gate.py), Phase 6.4 (audit.py)
**Parallel:** None (this is the integration point)

---

## Before You Start

```bash
cat mcp_proxy.py         # Full current proxy
cat proxy_config.py      # ProxyConfig and build_config
cat identity.py          # Phase 6.1 output
cat gate.py              # Phase 6.3 output (Gate with identity param)
cat audit.py             # Phase 6.4 output (log_tool_call with identity)
cat test_mcp_proxy.py    # Existing proxy test patterns
cat test_integration_mcp.py  # Integration test patterns
```

---

## Context

The MCP proxy is where identity resolution actually happens at runtime.  It:

1. Resolves identity at startup from environment/config (via `resolve_identity()`).
2. Passes the resolved `IdentityContext` to `Gate.__init__()`.
3. Includes identity fields in every `audit.log_tool_call()`.
4. Merges the proxy's existing `session_id` with the identity's `session_id`.

The proxy already generates a `session_id` (`str(uuid.uuid4())[:8]`).  After this phase, that session_id is passed to `resolve_identity()` so it becomes part of the IdentityContext and flows through consistently.

---

## Deliverables

### `mcp_proxy.py` Changes

```python
# Add import
from agent_gate.identity import IdentityContext, resolve_identity


class MCPProxy:
    def __init__(
        self,
        server_command: List[str],
        config: Optional[ProxyConfig] = None,
        server_name: Optional[str] = None,
    ):
        # ... existing ...
        self.session_id = str(uuid.uuid4())[:8]

        # Resolve identity from environment/config
        self.identity = self._resolve_identity()

        # ... existing ...

    def _resolve_identity(self) -> IdentityContext:
        """
        Resolve identity for this proxy session.

        Uses the policy's identity.fields configuration
        (if available) merged with environment variables.
        Passes the proxy's session_id so it's consistent
        across identity, gate, and audit.
        """
        # Identity config comes from the policy YAML
        # We need the policy loaded to get it, but policy
        # isn't loaded until _init_gate(). So we do a
        # lightweight read of just the identity section.
        identity_fields = self._read_identity_config()
        return resolve_identity(
            identity_config=identity_fields,
            session_id=self.session_id,
        )

    def _read_identity_config(self) -> Optional[dict]:
        """
        Read the identity.fields section from the policy YAML.

        This is a lightweight read — we don't validate the full
        policy here.  Full validation happens in _init_gate().
        Returns None if no identity section exists.
        """
        try:
            import yaml
            policy_path = self.config.policy_file
            if policy_path and os.path.exists(policy_path):
                with open(policy_path, "r") as f:
                    raw = yaml.safe_load(f)
                if isinstance(raw, dict):
                    return raw.get("identity", {}).get("fields")
        except Exception:
            pass
        return None

    def _init_gate(self) -> bool:
        """
        Initialize the Gate evaluation engine.

        Now passes identity to the Gate constructor.
        """
        errors = self.config.validate()
        if errors:
            for err in errors:
                _log(f"Config error: {err}")
            return False

        try:
            kwargs = self.config.to_gate_kwargs()
            kwargs["identity"] = self.identity  # NEW
            self.gate = Gate(**kwargs)
            _log(
                f"Gate initialized "
                f"(backend={self.config.classifier_backend}, "
                f"identity={self.identity.display_name})"
            )
            return True
        except Exception as e:
            _log(f"Failed to initialize gate: {e}")
            return False

    def _init_audit(self) -> None:
        """
        Initialize the audit logger.

        Uses session_id from identity for consistency.
        """
        self.audit = AuditLogger(
            path=self.config.audit_log,
            server_name=self.server_name,
            session_id=self.identity.session_id or self.session_id,
        )
        self.audit.log_proxy_event("proxy_started", {
            "server_command": " ".join(self.server_command),
            "config_source": self.config.config_source,
            "classifier_backend": self.config.classifier_backend,
            "identity": self.identity.to_dict(),  # NEW
        })

    def _handle_tool_call(self, msg: MCPMessage) -> Optional[dict]:
        # ... existing code ...

        # Update the audit.log_tool_call call to include identity:
        if self.audit:
            # ... existing fields ...
            self.audit.log_tool_call(
                tool_name=tool_name,
                arguments=tool_input,
                verdict=decision.verdict.value,
                tier=tier_value,
                reason=decision.reason,
                msg_id=msg.msg_id,
                vault_path=vault_path,
                duration_ms=round(duration_ms, 2),
                policy_hash=(
                    self.gate.policy.policy_hash
                    if self.gate else None
                ),
                rate_context=rate_ctx,
                # NEW identity fields:
                operator=self.identity.operator,
                agent_id=self.identity.agent_id,
                service_account=self.identity.service_account,
                role=self.identity.role,
            )
```

### `proxy_config.py` Changes

Update `to_gate_kwargs()` to support the identity parameter:

```python
class ProxyConfig:
    def to_gate_kwargs(self) -> dict:
        """Build kwargs dict for Gate.__init__."""
        kwargs = {
            "policy_path": self.policy_file,
            "workdir": self.workdir,
            "classifier_backend": self.classifier_backend,
        }
        # ... existing OPA config logic ...
        # Note: identity is NOT added here.
        # It's added by MCPProxy._init_gate() directly
        # because identity resolution is the proxy's concern.
        return kwargs
```

### `agent_gate_hook.py` and `agent_gate_hook_write.py` Changes

These Claude Code hook files should also resolve identity:

```python
# In agent_gate_hook.py, update gate initialization:
from agent_gate.identity import resolve_identity

identity = resolve_identity(session_id=SESSION_ID)
gate = Gate(
    policy_path=POLICY_PATH,
    workdir=WORKDIR,
    identity=identity,
)
```

---

## Test Cases

### File: `test_mcp_proxy_identity.py` (NEW)

```
# --- Identity Resolution ---

test_proxy_resolves_identity_from_env
    Set AGENT_GATE_OPERATOR="sean", AGENT_GATE_ROLE="admin"
    proxy = MCPProxy(server_command, config)
    → proxy.identity.operator == "sean"
    → proxy.identity.role == "admin"

test_proxy_identity_includes_session_id
    proxy = MCPProxy(server_command, config)
    → proxy.identity.session_id == proxy.session_id

test_proxy_no_identity_env_anonymous
    No AGENT_GATE_* env vars set
    proxy = MCPProxy(server_command, config)
    → proxy.identity.operator is None
    → proxy.identity.has_identity() is False

# --- Gate Initialization ---

test_init_gate_receives_identity
    Set AGENT_GATE_ROLE="admin"
    proxy = MCPProxy(server_command, config)
    proxy._init_gate()
    → proxy.gate.identity.role == "admin"

test_init_gate_no_identity_works
    No env vars
    proxy = MCPProxy(server_command, config)
    proxy._init_gate()
    → proxy.gate.identity is not None (has session_id)

# --- Audit Integration ---

test_audit_startup_includes_identity
    proxy._init_audit()
    → proxy_started event contains identity dict

test_audit_tool_call_includes_identity
    (Mock gate evaluation, verify audit.log_tool_call
     receives operator and role kwargs)

# --- Config Read ---

test_read_identity_config_from_yaml
    Use policy_with_identity.yaml
    config = proxy._read_identity_config()
    → config contains "operator", "role" keys

test_read_identity_config_missing_section
    Use default.yaml (no identity section)
    config = proxy._read_identity_config()
    → config is None
```

---

## Verification

```bash
python -m pytest test_mcp_proxy_identity.py -v
python -m pytest test_mcp_proxy.py -v  # Existing tests
python -m pytest -x -q  # All tests
# Expected: all existing + ~10 new pass
```

---

## Commit

```
Phase 6.6: MCP proxy identity resolution and propagation

- MCPProxy resolves identity at startup via resolve_identity()
- Identity passed to Gate constructor
- Identity fields included in all audit log_tool_call entries
- Proxy startup event includes identity context
- Session ID flows consistently from proxy → identity → audit
- agent_gate_hook.py updated for Claude Code integration
- 10 new tests in test_mcp_proxy_identity.py
- All existing proxy and integration tests pass
```
