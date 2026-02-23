# Phase 7 MODIFY Decision — Design Document

**Version:** v0.4.0
**Date:** 2026-02-23
**Status:** Approved design, pending implementation planning
**Prerequisite:** v0.3.0 (313 tests passing, identity binding, RBAC)
**AARM:** R4 (Five Authorization Decisions) — partial to improved
**Authoritative Reference:** `tasks/PHASE7_MODIFY_REFERENCE.md`

---

## 1.  What This Adds

A MODIFY verdict allows the gate to rewrite a tool call's parameters into a policy-compliant form and forward the modified call rather than denying it outright.  This is the difference between a firewall that drops a packet and a proxy that sanitizes it.

Examples:
- `chmod 777 deploy.sh` -> `chmod 755 deploy.sh` (permission clamped)
- `rm -rf /workspace/data/` -> `rm -r /workspace/data/` (force flag stripped)
- `SELECT * FROM users` -> `SELECT * FROM users LIMIT 100` (row limit appended)
- `curl http://api.example.com` -> `curl --max-time 30 http://api.example.com` (safety flag injected)

---

## 2.  Locked Decisions (from PHASE7_MODIFY_REFERENCE.md)

These are final.  The implementation must reflect them exactly.

**Loop ownership:** `mcp_proxy.py` owns the reinvocation loop.  `gate.evaluate()` returns `Verdict.MODIFY` with a `modified_tool_call` field.  The proxy catches that verdict, swaps the input dict, and calls `gate.evaluate()` again with `reinvocation=True`.  On reinvocation, the gate writes no audit record.  The proxy owns the single combined audit write after reinvocation completes.  Reinvocation depth capped at 1.

**Vault interaction:** Vault backup runs on the modified call's target, not the original.  Patterns with `vault: skip` bypass vault backup entirely.  `chmod` and `chown` must carry `vault: skip` in `default.yaml`.  The gate (`_handle_destructive()`) owns vault interaction and vault skip logic.  The proxy has no vault awareness and should not acquire any.

**Failure mode:** Fail closed.  If a modify operation cannot be applied cleanly, deny the action.

**OPA pattern:** Parallel Rego rule `modifications` returns a set of patch objects.  Non-empty `modifications` with `allow == false` signals MODIFY.

**Idempotency:** All operations must be idempotent.  Enforced in code.

**Canonical schema:** See Section 3 below.

---

## 3.  Schema

### New pattern-level fields

| Field | Type | Purpose |
|---|---|---|
| `args_match` | string (regex) | Regex match on full argument string |
| `modify` | dict | Rewrite operations block |
| `vault` | string | Pattern-level vault override (`skip` only in Phase 7) |

### Modify operation keys (inside `modify` dict)

| Key | Type | Example |
|---|---|---|
| `clamp_permission` | string | `"755"` |
| `strip_flags` | list of strings | `["-f"]` |
| `require_flags` | list of strings | `["--interactive"]` |
| `append_arg` | string | `"LIMIT 100"` |
| `max_depth` | integer | `2` |

### Example pattern

```yaml
- command: "chmod"
  description: "Permission change - clamp to policy maximum"
  vault: skip
  modify:
    clamp_permission: "755"
```

---

## 4.  Resolved Design Questions

### Q5: Role-scoped modification rules

**Decision:** Minimal scaffolding only.  Add `modify_rules` to `_validate_role_overrides()` as a valid override key so the parser accepts it without error.  No parsing logic, no storage.  Future phase adds real support.

### Q6: Modification chain ordering

**Decision:** First match wins.  The existing "first matching pattern" behavior in `_match_tier()` is preserved.  Only one pattern's `modify` block fires.  Within that block, operations apply in YAML declaration order (the order they appear in the `modify` dict).  No conflict resolution needed because only one pattern matches.

### Q7: Agent feedback format

**Decision:** Two new dedicated fields on `GateDecision`:
- `modified_tool_call: Optional[dict]` — the rewritten tool call
- `modification_feedback: Optional[dict]` — structured feedback per Reference Section 3.5

Do not reuse `denial_feedback` or `escalation_hint` for MODIFY verdicts.  `to_agent_message()` gains a MODIFY branch.  `to_dict()` includes modification data when present.

### Q8: Audit hash chaining with dual parameters

**Decision:** No special handling needed.  New Optional fields on `AuditRecord` (`original_tool_call`, `modified_tool_call`, `modification_rule`, `reinvocation_verdict`) are automatically included in the hash when non-None via the existing `sort_keys=True` serialization.  The existing `arguments` field always means "what the agent submitted" (original parameters).

---

## 5.  Data Flow

```
Agent proposes: chmod 777 deploy.sh
         |
         v
   mcp_proxy.py  (_handle_tool_call)
   |
   |  1. gate.evaluate(original_call)
   |     - classifier matches "chmod" pattern with modify block
   |     - gate builds modified_tool_call via modifier.py
   |     - gate returns Verdict.MODIFY + modified_tool_call + modification_feedback
   |     - gate writes NO audit record (proxy owns the write)
   |
   |  2. Proxy catches MODIFY, swaps input:
   |     original: {chmod 777 deploy.sh}
   |     modified: {chmod 755 deploy.sh}
   |
   |  3. gate.evaluate(modified_call, reinvocation=True)
   |     - classifier re-evaluates modified call through full pipeline
   |     - gate returns ALLOW (or DENY if still unsafe)
   |     - gate writes NO audit record (reinvocation=True suppresses)
   |
   |  4. Proxy assembles combined audit record:
   |     arguments: original params (what agent submitted)
   |     original_tool_call: full original call dict
   |     modified_tool_call: full modified call dict
   |     modification_rule: {rule_id, description, operations_applied}
   |     reinvocation_verdict: "allow" or "deny"
   |
   |  5. Routing:
   |     If reinvocation returned MODIFY -> DENY (depth cap=1, policy error)
   |     If reinvocation returned DENY -> DENY original action
   |     If reinvocation returned ALLOW -> forward modified call to server
   |
         |
         v
   chmod 755 deploy.sh executes
```

**Vault behavior:** When the modified call lands in the destructive tier during reinvocation, `_handle_destructive()` in gate.py checks the matched pattern for `vault: skip`.  If present, vault backup is suppressed.  If absent, vault backup runs on the modified call's target paths.  The proxy never touches vault logic.

---

## 6.  Component Changes

### 6.1  modifier.py (NEW)

Standalone module implementing the five modify operations.  Each operation is a pure function: `(args_string, operation_params) -> modified_args_string`.  All operations are idempotent.  On error, raises `ModificationError` (gate catches this and denies).

```python
class ModificationError(Exception): ...

def apply_modifications(command: str, args: List[str], modify_block: dict) -> tuple:
    """Apply all operations in YAML declaration order.  Returns (modified_args, operations_applied)."""

def clamp_permission(args: List[str], max_perm: str) -> List[str]: ...
def strip_flags(args: List[str], flags: List[str]) -> List[str]: ...
def require_flags(args: List[str], flags: List[str]) -> List[str]: ...
def append_arg(args: List[str], arg: str) -> List[str]: ...
def max_depth(args: List[str], depth: int) -> List[str]: ...
```

### 6.2  policy_loader.py

- Parse `modify` dict on pattern entries (validate operation keys against known set)
- Parse `args_match` string (validate as compilable regex)
- Parse `vault` string on pattern entries (validate only `skip` for Phase 7)
- Add `modify_rules` to valid role override keys (accept, ignore)

### 6.3  classifier_base.py + classifier.py

- `ClassificationResult` gains `modification_rules: Optional[dict] = None`
- `PythonClassifier._match_tier()` passes `modify` block from matched pattern into `ClassificationResult.modification_rules`
- `PythonClassifier._match_tier()` supports `args_match` regex matching (complement to `args_contain`)

### 6.4  gate.py

- `Verdict.MODIFY` added to enum
- `GateDecision` gains `modified_tool_call: Optional[dict] = None` and `modification_feedback: Optional[dict] = None`
- `GateDecision.to_dict()` includes modification data
- `GateDecision.to_agent_message()` gains MODIFY branch
- `evaluate()` accepts `reinvocation: bool = False` parameter
- When `reinvocation=True`, gate suppresses `_log_decision()`
- `_handle_destructive()` checks for `modify` key on matched pattern, delegates to `_handle_modify()` if present
- `_handle_modify()` calls `modifier.apply_modifications()`, builds modified tool call, returns `Verdict.MODIFY`
- `_handle_destructive()` respects `vault: skip` on matched pattern (skips vault backup)

### 6.5  audit.py

Four new Optional fields on `AuditRecord`:
- `original_tool_call: Optional[dict] = None`
- `modified_tool_call: Optional[dict] = None`
- `modification_rule: Optional[dict] = None`
- `reinvocation_verdict: Optional[str] = None`

`AuditLogger.log_tool_call()` gains corresponding parameters.  Hash chaining mechanism unchanged.

### 6.6  opa_classifier.py + yaml_to_rego.py

- `yaml_to_rego.py`: compile `modify` blocks from YAML patterns into `modifications` Rego rules
- `opa_classifier.py`: query both `data.agent_gate.decision` and `data.agent_gate.modifications`
- Non-empty `modifications` with `allow == false` maps to `Verdict.MODIFY` via gate

### 6.7  mcp_proxy.py

- `_handle_tool_call()` catches `Verdict.MODIFY`
- Swaps input dict for `decision.modified_tool_call`
- Calls `gate.evaluate()` again with `reinvocation=True`
- Depth guard: if second evaluation returns MODIFY, treat as policy error and deny
- Assembles combined audit record with all four MODIFY fields
- Forwards modified call to server on ALLOW

### 6.8  default.yaml + documentation

- Add `vault: skip` to `chmod` and `chown` patterns
- Add example `modify` blocks (chmod clamp, rm strip flags)
- Update README (pipeline diagram, verdict table, known limitations)
- Update ROADMAP (Phase 7 as completed)
- Update AARM_Alignment.md (R4 improvement)
- Update COMPLIANCE.md (new control mappings)

---

## 7.  Dependency Graph

```
Phase 7.1 (modifier.py)
    |
    v
Phase 7.2 (policy_loader.py)
    |
    +----------+----------+
    v          v          v
Phase 7.3  Phase 7.5  Phase 7.6
(classifier) (audit)   (opa+rego)
    |          |          |
    +------+---+          |
           v              |
      Phase 7.4           |
      (gate.py)           |
           |              |
           +------+-------+
                  v
            Phase 7.7
          (mcp_proxy.py)
                  |
                  v
            Phase 7.8
            (docs)
```

**Parallelizable after 7.2:** Phases 7.3, 7.5, 7.6 can run concurrently.

---

## 8.  Test Estimates

| Phase | File | New Tests |
|---|---|---|
| 7.1 | `test_modifier.py` | ~20 |
| 7.2 | `test_policy_loader_modify.py` | ~15 |
| 7.3 | `test_classifier_modify.py` | ~15 |
| 7.4 | `test_gate_modify.py` | ~20 |
| 7.5 | `test_audit_modify.py` | ~10 |
| 7.6 | `test_opa_modify.py` | ~15 |
| 7.7 | `test_mcp_proxy_modify.py` | ~20 |
| 7.8 | — | 0 |

**Estimated total new tests:** ~115
**Estimated total after phase:** ~428

---

## 9.  What Phase 7 Does Not Include

- Role-scoped modify rules (schema reserved, not activated)
- DEFER verdict (separate phase)
- STEP_UP approval service completion
- Modify rules sourced from OPA policy alone without YAML backing
- Vault `metadata_only` mode
- Composition of multiple matching modify patterns (first match wins)

---

## 10.  Rules for Implementation

1. Double spaces after periods in all prose.
2. Commas instead of em dashes.
3. Python 3.9 compatibility (no match statements, no type aliases, use Optional[]).
4. No new external dependencies.
5. Backward compatibility absolute (existing policies without modify work identically).
6. Each phase file includes: "Before You Start", deliverables, test cases, verification commands, commit message.
7. Target ~15-25 new tests per phase file.
8. Never use sed for file editing.
9. `tasks/PHASE7_MODIFY_REFERENCE.md` is authoritative.
10. One commit per phase.
