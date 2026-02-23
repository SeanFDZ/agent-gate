# Phase 7: MODIFY Decision — Implementation Master Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Version:** v0.4.0
**Target:** March 2026
**Prerequisite:** v0.3.0 (313 tests passing, identity binding, RBAC)
**AARM:** R4 (Five Authorization Decisions) — partial to improved
**Authoritative Reference:** `tasks/PHASE7_MODIFY_REFERENCE.md`

---

## Rules for All Agents

These rules are non-negotiable.  Every agent MUST follow them.

1. **Read before write.**  Read every file listed in "Before You Start" before writing a single line.  Confirm you understand the current structure.
2. **Never use `sed` for file editing.**  Use Python scripts, `str_replace`, or manual editing only.
3. **Double spaces after periods** in all comments, docstrings, and documentation.
4. **Commas instead of em dashes** in prose (comments, docstrings, docs).
5. **Python 3.9 compatibility.**  No `match` statements, no `type X = ...`, no `str | None` union syntax.  Use `Optional[str]` from typing.
6. **Imports use `agent_gate.` prefix.**  Example: `from agent_gate.modifier import apply_modifications`.
7. **Backward compatibility is absolute.**  The `modify` key on patterns is optional.  Every existing test must pass without modification after every phase.  Existing policies without `modify` rules work identically to v0.3.0.
8. **Run ALL tests after every phase.**  Command: `cd /path/to/repo && python -m pytest -x -q`.  All 313 existing tests plus new tests must pass.
9. **No new external dependencies.**  MODIFY uses stdlib only (re, json, dataclasses).
10. **One commit per phase.**  Commit message format: `Phase 7.X: <description>`.

---

## Architecture Overview

### MODIFY Data Flow

```
Agent proposes: chmod 777 deploy.sh
         |
         v
   mcp_proxy.py  (_handle_tool_call)
   |
   |  1. gate.evaluate(original_call)
   |     - classifier matches "chmod" pattern with modify block
   |     - gate builds modified_tool_call via modifier.py
   |     - gate returns Verdict.MODIFY + modified_tool_call + feedback
   |     - gate writes NO audit record (proxy owns the write)
   |
   |  2. Proxy catches MODIFY, swaps input:
   |     original: {chmod 777 deploy.sh}
   |     modified: {chmod 755 deploy.sh}
   |
   |  3. gate.evaluate(modified_call, reinvocation=True)
   |     - classifier re-evaluates modified call
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
   |     If reinvocation returned MODIFY -> DENY (depth cap=1)
   |     If reinvocation returned DENY -> DENY original action
   |     If reinvocation returned ALLOW -> forward modified call
   |
         |
         v
   chmod 755 deploy.sh executes
```

### YAML Schema Addition

```yaml
actions:
  destructive:
    patterns:
      # chmod: audit trail only, permission clamped to 755
      - command: "chmod"
        description: "Permission change, clamp to policy maximum"
        vault: skip
        modify:
          clamp_permission: "755"

      # rm -f: strip the force flag, keep the deletion
      - command: "rm"
        args_contain: ["-f"]
        description: "Force delete, strip -f flag"
        modify:
          strip_flags: ["-f"]

      # Unbounded SELECT: inject row limit
      - command: "database_query"
        args_match: "^SELECT"
        description: "Unbounded SELECT, enforce row limit"
        modify:
          append_arg: "LIMIT 100"

      # curl without timeout: inject safety timeout
      - command: "curl"
        args_match: "^(?!.*--max-time).*"
        description: "HTTP call without timeout, inject 30s limit"
        modify:
          require_flags: ["--max-time 30"]
```

### Canonical Schema

**New pattern-level fields:**

| Field | Type | Purpose |
|---|---|---|
| `args_match` | string (regex) | Regex match on full argument string |
| `modify` | dict | Rewrite operations block |
| `vault` | string | Pattern-level vault override (`skip` only in Phase 7) |

**Modify operation keys (inside `modify` dict):**

| Key | Type | Example |
|---|---|---|
| `clamp_permission` | string | `"755"` |
| `strip_flags` | list of strings | `["-f"]` |
| `require_flags` | list of strings | `["--interactive"]` |
| `append_arg` | string | `"LIMIT 100"` |
| `max_depth` | integer | `2` |

---

## Resolved Design Questions

### Q5: Role-scoped modification rules

**Decision:** Minimal scaffolding only.  Add `modify_rules` to `_validate_role_overrides()` as a valid override key so the parser accepts it without error.  No parsing logic, no storage.  Future phase adds real support.

### Q6: Modification chain ordering

**Decision:** First match wins.  The existing "first matching pattern" behavior in `_match_tier()` is preserved.  Only one pattern's `modify` block fires.  Within that block, operations apply in YAML declaration order (the order they appear in the `modify` dict).  No conflict resolution needed because only one pattern matches.

### Q7: Agent feedback format

**Decision:** Two new dedicated fields on `GateDecision`:
- `modified_tool_call: Optional[dict]`, the rewritten tool call
- `modification_feedback: Optional[dict]`, structured feedback per Reference Section 3.5

Do not reuse `denial_feedback` or `escalation_hint` for MODIFY verdicts.  `to_agent_message()` gains a MODIFY branch.  `to_dict()` includes modification data when present.

### Q8: Audit hash chaining with dual parameters

**Decision:** No special handling needed.  New Optional fields on `AuditRecord` (`original_tool_call`, `modified_tool_call`, `modification_rule`, `reinvocation_verdict`) are automatically included in the hash when non-None via the existing `sort_keys=True` serialization.  The existing `arguments` field always means "what the agent submitted" (original parameters).

---

## Phase Dependency Graph

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
**Phase 7.4** depends on 7.3 + 7.5 (classifier and audit must be done).
**Phase 7.7** depends on 7.4 + 7.6 (gate and OPA must be done).
**Phase 7.8** depends on all prior phases.

---

## Phase Summary

| Phase | File | Task | New Tests |
|---|---|---|---|
| 7.1 | `modifier.py` (NEW) | Standalone modify operations module | ~20 |
| 7.2 | `policy_loader.py` | Parse `modify`, `args_match`, `vault` keys; validate operations | ~15 |
| 7.3 | `classifier_base.py`, `classifier.py` | `modification_rules` on ClassificationResult, `args_match` regex support | ~15 |
| 7.4 | `gate.py` | `Verdict.MODIFY`, `_handle_modify()`, vault skip, reinvocation suppression | ~20 |
| 7.5 | `audit.py` | Four new Optional fields on AuditRecord, `log_tool_call()` parameters | ~10 |
| 7.6 | `opa_classifier.py`, `yaml_to_rego.py` | `modifications` Rego rule, OPA MODIFY signal | ~15 |
| 7.7 | `mcp_proxy.py` | Reinvocation loop, combined audit record, depth guard | ~20 |
| 7.8 | Docs | Update README, ROADMAP, AARM_Alignment, COMPLIANCE, default.yaml | 0 |

**Estimated total new tests:** ~115
**Estimated total after phase:** ~428

---

## Research Summary

### AARM R4 (Five Authorization Decisions)

AARM requires five verdicts: ALLOW, DENY, ESCALATE, MODIFY, DEFER.  Phase 7 adds MODIFY, bringing Agent Gate to 4 of 5.  DEFER remains a future phase.

### Industry Patterns

Research covered Kubernetes mutating admission webhooks, OPA Gatekeeper mutations, ProxySQL query rewriting, and ModSecurity WAF transforms.  Five consistent patterns emerged:

1. **Mutate-then-revalidate.**  Every system re-evaluates after mutation.  Agent Gate's reinvocation loop implements this.
2. **Log both original and modified.**  Forensic requirement.  Audit records capture both parameter sets.
3. **Fail closed.**  If mutation fails, deny.  Never pass unmodified form through.
4. **Declarative rules.**  Operations declared in policy, not coded in the gate.
5. **Idempotency required.**  All operations must be safe to apply twice.

### OPA MODIFY Pattern

OPA returns boolean decisions natively.  MODIFY requires structured rewrite data.  The pattern is a parallel Rego rule `modifications` that returns patch objects.  Non-empty `modifications` with `allow == false` signals MODIFY.  `yaml_to_rego.py` compiles `modify` blocks into these rules.

---

## What Phase 7 Does Not Include

- Role-scoped modify rules (schema reserved, not activated)
- DEFER verdict (separate phase)
- STEP_UP approval service completion
- Modify rules sourced from OPA policy alone without YAML backing
- Vault `metadata_only` mode
- Composition of multiple matching modify patterns (first match wins)
