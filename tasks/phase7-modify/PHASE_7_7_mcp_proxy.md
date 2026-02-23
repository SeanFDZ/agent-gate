# Phase 7.7: MCP Proxy — Reinvocation Loop and Combined Audit

**File:** `agent_gate/mcp_proxy.py` (MODIFY)
**Depends on:** Phase 7.4 (gate must return Verdict.MODIFY), Phase 7.6 (OPA must support MODIFY)
**Blocked by:** 7.4, 7.6

---

## Before You Start

Read these files to understand the current structure:

- `agent_gate/mcp_proxy.py` — `_handle_tool_call()`, `_init_gate()`, `_init_audit()`
- `agent_gate/gate.py` — `Verdict.MODIFY`, `GateDecision.modified_tool_call`, `evaluate(reinvocation=True)` (from Phase 7.4)
- `agent_gate/audit.py` — `log_tool_call()` with MODIFY params (from Phase 7.5)
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Sections 3.1 (Loop Ownership), 3.3 (Audit Record)

---

## Context

The proxy owns the reinvocation loop.  When `gate.evaluate()` returns `Verdict.MODIFY`:

1. The proxy catches it and extracts `decision.modified_tool_call`.
2. The proxy calls `gate.evaluate(modified_tool_call, reinvocation=True)`.
3. On reinvocation, the gate suppresses its own audit write.
4. The proxy examines the reinvocation verdict:
   - **ALLOW**: Forward the modified call to the server.  Write a combined audit record.
   - **DENY**: Deny the original action.  Write a combined audit record with `reinvocation_verdict="deny"`.
   - **MODIFY** (depth cap exceeded): Treat as policy error.  Deny and log error.
   - **ESCALATE**: Treat as DENY for the modified call.
5. The proxy assembles one combined audit record with all four MODIFY fields.
6. The proxy has NO vault awareness.  Vault logic lives in `gate.py`'s `_handle_destructive()`.

---

## Deliverables

### Changes to `agent_gate/mcp_proxy.py`

**Update `_handle_tool_call()` to handle Verdict.MODIFY:**

```python
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
        if self.audit:
            ph = self.gate.policy.policy_hash if self.gate else None
            self.audit.log_tool_call(
                tool_name=tool_name,
                arguments=tool_input,
                verdict="deny",
                tier="error",
                reason=f"Gate evaluation error: {e}",
                msg_id=msg.msg_id,
                policy_hash=ph,
            )
        return make_error_response(
            msg.msg_id, -32603,
            f"Agent Gate: internal error during evaluation",
        )

    duration_ms = (time.time() - start_time) * 1000

    # Handle MODIFY verdict — reinvocation loop
    if decision.verdict == Verdict.MODIFY:
        return self._handle_modify_verdict(
            msg, decision, gate_input, tool_name, tool_input,
            start_time, duration_ms,
        )

    # Audit the decision (non-MODIFY path, unchanged)
    if self.audit:
        self._audit_decision(
            decision, tool_name, tool_input, msg.msg_id, duration_ms
        )

    # Route based on verdict (existing logic, unchanged)
    if decision.verdict == Verdict.ALLOW:
        _log(f"ALLOW: {tool_name} ({round(duration_ms, 1)}ms)")
        return None

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

    return make_error_response(
        msg.msg_id, -32603,
        "Agent Gate: unexpected verdict",
    )


def _handle_modify_verdict(
    self,
    msg: MCPMessage,
    decision: "GateDecision",
    original_gate_input: dict,
    tool_name: str,
    tool_input: dict,
    start_time: float,
    initial_duration_ms: float,
) -> Optional[dict]:
    """
    Handle a MODIFY verdict: reinvoke the gate with modified call,
    then route based on the reinvocation result.

    Returns None if the modified call is ALLOWED (forward to server).
    Returns an error response dict if denied.
    """
    modified_tool_call = decision.modified_tool_call
    if not modified_tool_call:
        _log(f"MODIFY without modified_tool_call — denying")
        return make_error_response(
            msg.msg_id, -32603,
            "Agent Gate: MODIFY verdict missing modified_tool_call",
        )

    _log(
        f"MODIFY: {tool_name} — reinvoking with modified call"
    )

    # Reinvoke the gate with the modified call
    try:
        reinvoke_decision = self.gate.evaluate(
            modified_tool_call, reinvocation=True
        )
    except Exception as e:
        _log(f"Reinvocation error: {e}")
        reinvoke_decision = None

    total_duration_ms = (time.time() - start_time) * 1000

    # Determine reinvocation verdict
    if reinvoke_decision is None:
        reinvocation_verdict = "error"
        final_verdict = "deny"
    elif reinvoke_decision.verdict == Verdict.MODIFY:
        # Depth cap exceeded — policy error
        _log(
            f"MODIFY on reinvocation (depth cap exceeded) — "
            f"denying as policy error"
        )
        reinvocation_verdict = "modify"
        final_verdict = "deny"
    elif reinvoke_decision.verdict == Verdict.ALLOW:
        reinvocation_verdict = "allow"
        final_verdict = "modify"  # Original verdict was MODIFY
    elif reinvoke_decision.verdict == Verdict.DENY:
        reinvocation_verdict = "deny"
        final_verdict = "deny"
    elif reinvoke_decision.verdict == Verdict.ESCALATE:
        reinvocation_verdict = "escalate"
        final_verdict = "deny"
    else:
        reinvocation_verdict = "unknown"
        final_verdict = "deny"

    # Assemble combined audit record
    if self.audit:
        # Build modification_rule dict
        feedback = decision.modification_feedback or {}
        modification_rule = {
            "rule_id": feedback.get("policy_rule", "unknown"),
            "description": feedback.get("reason", decision.reason),
            "operations_applied": feedback.get("operations_applied", []),
        }

        tier_value = (
            decision.classification.tier.value
            if decision.classification else "unknown"
        )

        self.audit.log_tool_call(
            tool_name=tool_name,
            arguments=tool_input,  # Always the original
            verdict=final_verdict,
            tier=tier_value,
            reason=decision.reason,
            msg_id=msg.msg_id,
            duration_ms=round(total_duration_ms, 2),
            policy_hash=(
                self.gate.policy.policy_hash if self.gate else None
            ),
            operator=self.identity.operator,
            agent_id=self.identity.agent_id,
            service_account=self.identity.service_account,
            role=self.identity.role,
            # MODIFY-specific fields
            original_tool_call=original_gate_input,
            modified_tool_call=modified_tool_call,
            modification_rule=modification_rule,
            reinvocation_verdict=reinvocation_verdict,
        )

    # Route based on reinvocation result
    if reinvocation_verdict == "allow":
        _log(
            f"MODIFY+ALLOW: {tool_name} "
            f"({round(total_duration_ms, 1)}ms)"
        )
        # Swap the message content to use modified tool call
        # The MCP message forwarded to the server uses modified params
        msg.raw = self._rebuild_tool_call_message(
            msg.raw, modified_tool_call
        )
        return None  # Forward modified call to server

    else:
        reason = (
            f"Action modified but reinvocation returned "
            f"{reinvocation_verdict}."
        )
        _log(f"MODIFY+DENY: {tool_name} — {reason}")
        tier = (
            decision.classification.tier.value
            if decision.classification else "unknown"
        )
        return make_gate_denial(
            msg_id=msg.msg_id,
            reason=reason,
            tier=tier,
        )


def _rebuild_tool_call_message(
    self, original_raw: dict, modified_tool_call: dict
) -> dict:
    """
    Rebuild the raw MCP message with modified tool call parameters.

    The proxy forwards the modified call to the server, so the
    message body must reflect the modified arguments.
    """
    rebuilt = dict(original_raw)
    params = dict(rebuilt.get("params", {}))
    modified_input = modified_tool_call.get("input", {})
    if "arguments" in params:
        params["arguments"] = modified_input
    elif "input" in params:
        params["input"] = modified_input
    rebuilt["params"] = params
    return rebuilt


def _audit_decision(
    self,
    decision: "GateDecision",
    tool_name: str,
    tool_input: dict,
    msg_id,
    duration_ms: float,
) -> None:
    """Audit a non-MODIFY decision (extracted for readability)."""
    vault_path = None
    if hasattr(decision, 'vault_result') and decision.vault_result:
        vault_path = getattr(
            decision.vault_result, 'backup_path', None
        )

    tier_value = (
        decision.classification.tier.value
        if decision.classification else "unknown"
    )
    rate_ctx = None
    if tier_value == "rate_limited" and self.gate:
        rate_ctx = self.gate.rate_tracker.get_rate_context()

    self.audit.log_tool_call(
        tool_name=tool_name,
        arguments=tool_input,
        verdict=decision.verdict.value,
        tier=tier_value,
        reason=decision.reason,
        msg_id=msg_id,
        vault_path=vault_path,
        duration_ms=round(duration_ms, 2),
        policy_hash=(
            self.gate.policy.policy_hash if self.gate else None
        ),
        rate_context=rate_ctx,
        operator=self.identity.operator,
        agent_id=self.identity.agent_id,
        service_account=self.identity.service_account,
        role=self.identity.role,
    )
```

---

## Test Cases

### File: `tests/test_mcp_proxy_modify.py` (NEW)

```
test_modify_verdict_triggers_reinvocation
    Mock gate returns Verdict.MODIFY on first call, Verdict.ALLOW on second
    -> _handle_tool_call returns None (forward to server)
    -> gate.evaluate called twice

test_modify_audit_record_has_all_fields
    Mock gate returns MODIFY then ALLOW
    -> audit.log_tool_call called with original_tool_call, modified_tool_call,
       modification_rule, reinvocation_verdict="allow"

test_modify_arguments_field_is_original
    Mock gate returns MODIFY then ALLOW
    -> audit arguments param is the original tool_input (not modified)

test_modify_reinvocation_deny
    Mock gate returns MODIFY then DENY
    -> _handle_tool_call returns denial response
    -> reinvocation_verdict="deny"

test_modify_reinvocation_modify_depth_cap
    Mock gate returns MODIFY on both calls
    -> _handle_tool_call returns denial response
    -> reinvocation_verdict="modify" (depth cap)

test_modify_reinvocation_escalate_treated_as_deny
    Mock gate returns MODIFY then ESCALATE
    -> _handle_tool_call returns denial
    -> reinvocation_verdict="escalate"

test_modify_reinvocation_error
    Mock gate returns MODIFY, second call raises Exception
    -> _handle_tool_call returns denial
    -> reinvocation_verdict="error"

test_modify_missing_modified_tool_call
    Mock gate returns MODIFY with modified_tool_call=None
    -> returns error response

test_modify_forwards_modified_message
    Mock gate returns MODIFY then ALLOW
    -> forwarded message has modified params, not original

test_rebuild_tool_call_message
    original_raw = {"params": {"arguments": {"command": "chmod 777 f"}}}
    modified = {"input": {"command": "chmod 755 f"}}
    rebuilt = _rebuild_tool_call_message(original_raw, modified)
    -> rebuilt["params"]["arguments"]["command"] == "chmod 755 f"

test_modify_single_audit_record
    Mock gate returns MODIFY then ALLOW
    -> audit.log_tool_call called exactly once (not twice)

test_modify_audit_verdict_field
    Mock gate returns MODIFY then ALLOW
    -> audit verdict="modify" (not "allow")

test_modify_duration_includes_reinvocation
    Mock gate returns MODIFY then ALLOW (with delay)
    -> duration_ms covers both evaluations

test_non_modify_path_unchanged
    Mock gate returns ALLOW directly
    -> existing behavior preserved, no reinvocation

test_deny_path_unchanged
    Mock gate returns DENY directly
    -> existing behavior preserved

test_escalate_path_unchanged
    Mock gate returns ESCALATE directly
    -> existing behavior preserved

test_audit_decision_helper_non_modify
    _audit_decision() called for ALLOW verdict
    -> log_tool_call called without modify fields

test_modify_reinvocation_uses_reinvocation_flag
    Mock gate returns MODIFY then ALLOW
    -> second gate.evaluate() called with reinvocation=True

test_proxy_has_no_vault_awareness
    Verify MCPProxy class has no vault-related attributes or methods
    -> no vault import, no vault logic

test_modify_log_message
    Mock gate returns MODIFY then ALLOW
    -> stderr contains "MODIFY" and "MODIFY+ALLOW"
```

---

## Verification

```bash
# Run just the new tests
python -m pytest tests/test_mcp_proxy_modify.py -v

# Run ALL tests to confirm no regressions
python -m pytest -x -q

# Expected: all existing tests pass, ~20 new tests pass
```

---

## Commit

```
Phase 7.7: MCP proxy reinvocation loop and combined audit

Modified: agent_gate/mcp_proxy.py
- _handle_tool_call() catches Verdict.MODIFY
- _handle_modify_verdict() owns reinvocation loop
- Depth cap: MODIFY on reinvocation -> DENY (policy error)
- Combined audit record with all four MODIFY fields
- _rebuild_tool_call_message() for forwarding modified calls
- _audit_decision() extracted for readability
- No vault awareness (gate owns vault logic)
- ~20 new tests in tests/test_mcp_proxy_modify.py
```
