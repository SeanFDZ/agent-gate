# Phase 7 Planning: MODIFY Decision (v0.4.0)

## Task

Create a detailed implementation plan for Phase 7 of Agent Gate — the MODIFY verdict.  This is the same format we used for Phase 6 (Identity Binding): a MASTER.md with architecture, rules, and research summary, followed by individual PHASE_7_X task files that Claude Code agents can execute independently.

## What Agent Gate Is

Agent Gate is an execution authority layer that intercepts AI agent tool calls before execution and enforces policy-based authorization.  It currently supports three verdicts: ALLOW, DENY, ESCALATE.  Phase 7 adds MODIFY — rewriting tool call parameters to make them safe rather than blocking them outright.

## Files to Read Before Planning

Read these files in this order.  The first two are authoritative over everything else.

**Locked design decisions (read these first, treat as ground truth):**
- `tasks/PHASE7_MODIFY_REFERENCE.md` — all architecture decisions, canonical schema names, audit record spec, and vault behavior are locked here.  Do not re-derive or override these decisions during planning.
- `tasks/agent_gate_modify_research.md` — research findings from AARM R4, Kubernetes mutating webhooks, OPA Gatekeeper, ProxySQL, and ModSecurity that inform the decisions above.

**Current codebase (read to understand integration points):**
- `README.md` — full system overview, pipeline diagram, design principles
- `ROADMAP.md` — Phase 7 section has the original intent; the MODIFY reference above supersedes it where they differ
- `gate.py` — `Gate.evaluate()` and `GateDecision`, the core decision pipeline
- `classifier_base.py` — `ClassificationResult` and the shared pre-processing layer
- `classifier.py` — Python backend pattern matching
- `opa_classifier.py` — OPA backend evaluation
- `mcp_proxy.py` — how verdicts are translated to MCP protocol actions
- `audit.py` — `AuditRecord` structure and hash chaining
- `yaml_to_rego.py` — how YAML policy compiles to Rego
- `policy_loader.py` — YAML schema validation
- `AARM_Alignment.md` — R4 (Five Authorization Decisions) current state
- `COMPLIANCE.md` — current NIST mapping

## What MODIFY Means

Instead of binary allow/deny, the gate rewrites tool call parameters before forwarding.  Examples:

- `chmod 777 deploy.sh` → `chmod 755 deploy.sh` (permission clamped)
- `rm -rf /workspace/data/` → `rm -r /workspace/data/` (force flag stripped)
- `SELECT * FROM users` → `SELECT * FROM users LIMIT 100` (row limit appended)
- `curl http://api.example.com` → `curl --max-time 30 http://api.example.com` (safety flag injected)

The agent receives structured feedback about what was modified and why.  Audit records capture both original and modified parameters.

## Locked Decisions — Do Not Re-Derive These

The following decisions are final.  The planning output must reflect them exactly.

**Loop ownership:** `mcp_proxy.py` owns the reinvocation loop.  `gate.evaluate()` returns `Verdict.MODIFY` with a `modified_tool_call` field.  The proxy catches that verdict, swaps the input dict, and calls `gate.evaluate()` again with `reinvocation=True`.  The gate suppresses the second audit record.  The proxy assembles one combined record.  Reinvocation depth is capped at 1 — if the second evaluation also returns MODIFY, treat it as a policy error and deny.

**Vault interaction:** Vault backup runs on the modified call's target, not the original.  Patterns may carry a `vault: skip` key (string, not boolean) to suppress vault backup entirely.  `chmod` and `chown` must carry `vault: skip` in `default.yaml` because permission changes do not alter file content — the correct artifact is an audit record, not a vault snapshot.

**Failure mode:** Fail closed.  If a modify operation cannot be applied cleanly, deny the action.  Do not allow the unmodified form through.

**OPA MODIFY pattern:** Add a parallel Rego rule `modifications` returning a set of patch objects.  The gate queries both `data.agent_gate.allow` and `data.agent_gate.modifications`.  A non-empty `modifications` set alongside `allow == false` signals MODIFY.  `yaml_to_rego.py` compiles `modify` blocks to `modifications` rules.

**Idempotency:** All modify operations must be idempotent.  Applying any operation to already-modified parameters must be a no-op.  Enforce in code, not just documentation.

## Canonical Schema — Use These Names Exactly

These are the locked field names.  The ROADMAP.md sketch used different names, which are superseded.

**New pattern-level fields:**

| Field | Type | Purpose |
|---|---|---|
| `args_match` | string (regex) | Regex match on full argument string, complement to `args_contain` |
| `modify` | dict | Rewrite operations block |
| `vault` | string | Pattern-level vault override.  Only valid value in Phase 7 is `skip` |

**Modify operation keys inside the `modify` dict:**

| Key | Type | Example |
|---|---|---|
| `clamp_permission` | string | `"755"` |
| `strip_flags` | list of strings | `["-f"]` |
| `require_flags` | list of strings | `["--interactive"]` |
| `append_arg` | string | `"LIMIT 100"` |
| `max_depth` | integer | `2` |

**Example pattern entry showing all new fields in context:**
```yaml
- command: "chmod"
  description: "Permission change — clamp to policy maximum"
  vault: skip
  modify:
    clamp_permission: "755"
```

## Design Questions Still Requiring Agent Judgment

The following questions were not fully resolved in the research phase.  The planning agent should reason through them and document the chosen approach in MASTER.md.

**5. Role-scoped modification rules** — Can roles define different modify rules (e.g., a developer role allows LIMIT 1000 where a reporting role allows LIMIT 10000)?  The schema in the MODIFY reference reserves `roles.*.modify_rules` but does not activate it.  The plan must decide whether Phase 7 activates this or defers it, and if deferred, what schema scaffolding (if any) gets added now.

**6. Modification chain ordering** — Can multiple `modify` operations match the same tool call?  If so, what is the composition order — policy file order, severity order, or something else?  What happens if two operations conflict (e.g., two `clamp_permission` rules with different values)?

**7. Agent feedback format** — The structured feedback shape is defined in the MODIFY reference (Section 3.5).  The planning agent should determine how this maps to the existing `GateDecision.denial_feedback` and `escalation_hint` fields — does MODIFY reuse these fields or add new fields to `GateDecision`?

**8. Audit hash chaining with dual parameters** — The original and modified parameters both appear in the audit record.  The hash chain must produce a deterministic record.  Clarify which fields are included in the hash computation and in what order, such that the chain remains tamper-evident across both parameter sets.

## Rules for the Plan

1. Double spaces after periods in all prose.
2. Commas instead of em dashes.
3. Python 3.9 compatibility — no `match` statements, no type aliases, use `Optional[]`.
4. No new external dependencies.
5. Backward compatibility is absolute — existing policies without `modify` rules work identically.
6. Each phase file must include: "Before You Start" (files to read), deliverables, test cases, verification commands, and commit message.
7. Target ~15-25 new tests per phase file, building on the existing 313.
8. Never use sed for file editing.
9. `tasks/PHASE7_MODIFY_REFERENCE.md` is authoritative.  If the plan conflicts with it, the plan is wrong.

## Output Format

Produce files in `tasks/phase7-modify/`:
- `MASTER.md` — architecture summary (referencing locked decisions), research summary, dependency graph between task files, and resolution of the four open questions above
- `PHASE_7_1_*.md` through `PHASE_7_N_*.md` — individual task files

Follow the exact structure used in Phase 6.  Read the Phase 6 plan files in `tasks/phase6-identity/` for reference on format and level of detail.
