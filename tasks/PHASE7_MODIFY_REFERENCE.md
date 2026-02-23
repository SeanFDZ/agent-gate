# Agent Gate — Phase 7 MODIFY Decision: Locked Design Reference

**Version:** Pre-implementation lock  
**Date:** 2026-02-23  
**Status:** Decisions locked.  Do not change field names or architecture without updating this document.

This document is the authoritative reference for any agent or developer implementing Phase 7.  It supersedes the Phase 7 section in ROADMAP.md where the two conflict.  ROADMAP.md carries forward-looking intent; this document carries locked implementation decisions.

---

## 1.  What Phase 7 Adds

A MODIFY verdict allows the gate to rewrite a tool call's parameters into a policy-compliant form and forward the modified call rather than denying it outright.

This is the difference between a firewall that drops a packet and a proxy that sanitizes it.  The agent's intent is preserved where possible; the dangerous form of the action is not.

Examples:
- `chmod 777 deploy.sh` → `chmod 755 deploy.sh` (permission clamped)
- `rm -rf /workspace/data/` → `rm -r /workspace/data/` (force flag stripped)
- `SELECT * FROM users` → `SELECT * FROM users LIMIT 100` (row limit appended)
- `curl http://api.example.com` → `curl --max-time 30 http://api.example.com` (safety flag injected)

---

## 2.  Locked YAML Schema

### 2.1  New Fields Added to Pattern Entries

All new fields are siblings of the existing `command`, `args_contain`, `condition`, and `description` fields.  No existing fields are renamed or removed.

| New Field | Type | Purpose |
|---|---|---|
| `args_match` | string (regex) | Match on full argument string using regex (complement to `args_contain` substring list) |
| `modify` | dict | Rewrite operations to apply when this pattern matches |
| `vault` | string | Override vault behavior at pattern level (see Section 2.3) |

### 2.2  Modify Operation Keys (canonical names — do not alter)

All operations live inside the `modify` dict on a pattern entry.

| Key | Type | What it does |
|---|---|---|
| `clamp_permission` | string | Maximum octal permission value.  Any higher permission is rewritten down to this value.  Example: `"755"` |
| `strip_flags` | list of strings | Remove listed flags from the argument string.  Example: `["-f"]` removes force flag from `rm` |
| `require_flags` | list of strings | Inject listed flags if not already present.  Example: `["--interactive"]` |
| `append_arg` | string | Append a literal string to the argument if not already present.  Idempotent.  Example: `"LIMIT 100"` |
| `max_depth` | integer | Limit recursive depth for commands that accept a depth argument.  Example: `2` |

**Naming rationale:** snake_case throughout, matching all existing YAML field conventions (`args_contain`, `allowed_paths`, etc.).  Singular vs. plural follows the value type: scalar operations (`clamp_permission`, `max_depth`, `append_arg`) are singular; list operations (`strip_flags`, `require_flags`) are plural.

### 2.3  Pattern-Level Vault Override

`chmod` and `chown` change permissions and ownership, not file content.  A vault snapshot of a file before `chmod` captures content that is identical post-`chmod` — the backup has no rollback value.  The correct artifact for these operations is an audit record, not a vault snapshot.

Add a `vault: skip` key to any pattern where vault backup should not run.  The audit record is always written regardless of this setting.

```yaml
- command: "chmod"
  description: "Permission change — audit only, no vault backup"
  vault: skip
  modify:
    clamp_permission: "755"
```

Future values (`vault: metadata_only`, etc.) are reserved.  Do not use a boolean here.

### 2.4  Complete Example — Annotated

```yaml
actions:
  destructive:
    patterns:
      # chmod: audit trail only, permission clamped to 755
      - command: "chmod"
        description: "Permission change — clamp to policy maximum"
        vault: skip
        modify:
          clamp_permission: "755"

      # rm -f: strip the force flag, keep the deletion
      - command: "rm"
        args_contain: ["-f"]
        description: "Force delete — strip -f flag"
        modify:
          strip_flags: ["-f"]

      # Unbounded SELECT: inject row limit
      - command: "database_query"
        args_match: "^SELECT"
        description: "Unbounded SELECT — enforce row limit"
        modify:
          append_arg: "LIMIT 100"

      # curl without timeout: inject safety timeout
      - command: "curl"
        args_match: "^(?!.*--max-time).*"
        description: "HTTP call without timeout — inject 30s limit"
        modify:
          require_flags: ["--max-time 30"]
```

### 2.5  Role-Scoped Modify Rules (Phase 7 Schema Reservation)

Phase 7 does not implement role-scoped modification rules, but the schema must accommodate them to avoid a breaking change in Phase 8.  The `roles` section (introduced in Phase 6) should reserve the following structure:

```yaml
roles:
  developer:
    modify_rules:
      - command: "database_query"
        modify:
          append_arg: "LIMIT 1000"
  reporting:
    modify_rules:
      - command: "database_query"
        modify:
          append_arg: "LIMIT 10000"
```

Phase 7 parser should read but silently ignore `roles.*.modify_rules` — it will be activated in a later phase.

---

## 3.  Architecture Decisions

### 3.1  Loop Ownership: The Proxy, Not the Gate

**Decision:** `mcp_proxy.py` owns the reinvocation loop.  `gate.evaluate()` does not call itself.

**Rationale:** Industry pattern across Kubernetes admission webhooks, OPA Gatekeeper, and ProxySQL is consistent — the orchestration layer owns the loop; the evaluator owns the decision.  `gate.evaluate()` already has a clean single-call contract.  Widening that contract to include self-reinvocation would complicate the gate's test surface without adding value.

**Implementation:**
1. `gate.evaluate()` returns `GateDecision(verdict=Verdict.MODIFY, modified_tool_call={...})` when a modify rule matches.
2. `mcp_proxy._handle_tool_call()` catches `Verdict.MODIFY`, swaps the input dict for `decision.modified_tool_call`, and calls `gate.evaluate()` again with `reinvocation=True`.
3. The gate uses `reinvocation=True` to suppress emitting a second audit record.
4. The proxy assembles one combined audit record after the second evaluation completes (see Section 3.3).

**Failure mode:** If the gate returns `Verdict.MODIFY` on the second evaluation (i.e., modification produced another modifiable call), the proxy treats this as a policy error, denies the action, and logs an error.  Reinvocation loop depth is capped at 1.

### 3.2  Vault Interaction with MODIFY

The vault operates on tier classification, not on argument values.  A MODIFY'd call that remains in the destructive tier still triggers vault backup — on the **modified** parameters.

This is the correct behavior: the vault is protecting the target file's pre-execution state, which is independent of which permission value is being applied.

Exception: patterns with `vault: skip` bypass the snapshot step regardless of tier.  For `chmod` and `chown`, this is the correct posture — audit the change, do not waste vault storage on content-identical snapshots.

### 3.3  Audit Record for MODIFY

One audit record per original tool call.  The reinvocation does not produce a second record.

Required fields added to `AuditRecord` for MODIFY decisions:

| Field | Type | Description |
|---|---|---|
| `original_tool_call` | dict | The unmodified tool call as the agent submitted it |
| `modified_tool_call` | dict | The rewritten tool call as forwarded to the server |
| `modification_rule` | dict | `{rule_id, description, operations_applied}` |
| `reinvocation_verdict` | string | The verdict returned by the second gate evaluation |

Existing fields (`timestamp`, `session_id`, `policy_hash`, `record_hash`) are unchanged.

**Pre-modification parameters must always be preserved.**  This is the forensic requirement — reviewers must be able to see what the agent originally requested, not just what was executed.

### 3.4  OPA Backend MODIFY Pattern

OPA returns boolean decisions natively.  MODIFY requires returning structured rewrite data alongside the decision.

**Pattern:** Add a parallel Rego rule `modifications` that returns a set of patch objects when the action would otherwise be denied but a safe form exists.  The gate queries both `data.agent_gate.allow` and `data.agent_gate.modifications`.  A non-empty `modifications` set with `allow == false` signals a MODIFY decision.

```rego
modifications[patch] {
    input.tool == "bash"
    contains(input.arguments.command, "chmod")
    patch := {
        "operation": "clamp_permission",
        "target_arg": "command",
        "max_value": "755"
    }
}
```

`yaml_to_rego.py` must be extended to compile `modify` blocks from YAML patterns into corresponding `modifications` rules in Rego.

### 3.5  Agent Feedback

The gate returns a structured modification notice to the agent explaining what changed and why.  The agent should not be surprised by the modified call — it should understand that its request was accepted in a constrained form.

```json
{
  "verdict": "MODIFY",
  "original_call": {"tool": "bash", "args": "chmod 777 deploy.sh"},
  "modified_call": {"tool": "bash", "args": "chmod 755 deploy.sh"},
  "reason": "Permission clamped to 755 per policy rule chmod-clamp-prod",
  "policy_rule": "chmod-clamp-prod"
}
```

---

## 4.  Idempotency Requirement

All modify operations must produce the same result when applied to already-modified parameters.  This is not optional — the reinvocation architecture (Section 3.1) can theoretically call the modifier twice if a proxy restart or error condition triggers a replay.

| Operation | Idempotency guarantee |
|---|---|
| `clamp_permission` | Applying `clamp_permission: "755"` to `chmod 755` is a no-op |
| `strip_flags` | Stripping `-f` from a command that doesn't have `-f` is a no-op |
| `require_flags` | Injecting `--interactive` when already present is a no-op |
| `append_arg` | Appending `LIMIT 100` when already present is a no-op |
| `max_depth` | Clamping depth on a command already at or below the limit is a no-op |

The modifier implementation must enforce these guarantees in code, not just in documentation.

---

## 5.  Failure Mode

If a modify operation cannot be applied cleanly (malformed argument, regex match failure, type mismatch), the gate denies the action rather than allowing the unmodified form through.

This is the same posture as Kubernetes `failurePolicy: Fail` — security-critical modifications fail closed.  An unmodified `chmod 777` getting through because the clamping logic errored is worse than a denied `chmod` that the agent retries with a corrected literal value.

Agent feedback on modification failure includes: original call, intended modification, failure reason, and escalation path.

---

## 6.  Files Requiring Changes

| File | Change |
|---|---|
| `gate.py` | Add `Verdict.MODIFY`, implement `_handle_modify()`, update `_handle_destructive()` to check for `modify` key and delegate, respect `vault: skip` |
| `classifier_base.py` | `ClassificationResult` carries `modification_rules: Optional[dict]` from matched pattern |
| `classifier.py` | `_match_tier()` passes `modify` block from matched pattern into `ClassificationResult.modification_rules` |
| `mcp_proxy.py` | `_handle_tool_call()` catches `Verdict.MODIFY`, owns reinvocation loop, assembles combined audit record |
| `audit.py` | Add `original_tool_call`, `modified_tool_call`, `modification_rule`, `reinvocation_verdict` to `AuditRecord` |
| `yaml_to_rego.py` | Compile `modify` blocks to `modifications` Rego rules |
| `default.yaml` | Add `vault: skip` to `chmod` and `chown` patterns; optionally add example `modify` blocks |
| `policy_loader.py` | Parse `vault` key at pattern level; parse `modify` dict; validate operation keys |

---

## 7.  What Phase 7 Does Not Include

These items are explicitly deferred to avoid scope creep:

- Role-scoped modify rules (schema reserved, not activated)
- DEFER verdict (R4 remaining gap — separate phase)
- STEP_UP approval service completion
- Modify rules sourced from OPA policy alone without YAML backing
- Vault `metadata_only` mode for permission changes

---

## 8.  AARM Advancement on Completion

| Requirement | Before Phase 7 | After Phase 7 |
|---|---|---|
| R4 (Five Authorization Decisions) | ⚠️ Partial — ALLOW, DENY, ESCALATE | ⚠️ Improved — ALLOW, DENY, ESCALATE, MODIFY (DEFER still missing) |
| R5 (Signed Receipts) | ⚠️ Partial | ⚠️ Improved — receipts now bind both original and modified params |

---

*This document was produced from research sessions covering AARM R4, Kubernetes mutating admission webhooks, OPA Gatekeeper mutations, ProxySQL query rewriting, and ModSecurity WAF transforms.  See `tasks/agent_gate_modify_research.md` for full research findings.*
