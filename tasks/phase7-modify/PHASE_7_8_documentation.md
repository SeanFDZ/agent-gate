# Phase 7.8: Documentation and Default Policy Updates

**Files:** `policies/default.yaml` (MODIFY), `README.md` (MODIFY), `ROADMAP.md` (MODIFY), `AARM_Alignment.md` (MODIFY), `COMPLIANCE.md` (MODIFY)
**Depends on:** All prior phases (7.1-7.7)
**Parallel:** None (this is the final phase)

---

## Before You Start

Read these files:

- `policies/default.yaml` — Current default policy (no modify blocks yet)
- `README.md` — System overview, pipeline diagram, verdict table
- `ROADMAP.md` — Phase 7 section describing MODIFY
- `AARM_Alignment.md` — Current alignment status for R4 and R5
- `COMPLIANCE.md` — NIST control mappings
- `tasks/PHASE7_MODIFY_REFERENCE.md` — Section 8 (AARM Advancement)

---

## Context

This phase updates documentation and the default policy to reflect the MODIFY verdict.  No new code, no new tests.

---

## Deliverables

### 1. Update `policies/default.yaml`

Add `vault: skip` to `chmod` and `chown` patterns.  Add example `modify` blocks:

```yaml
  destructive:
    description: "Actions that modify or destroy data. Trigger mandatory vault backup."
    patterns:
      - command: "rm"
        description: "File deletion"
      - command: "mv"
        description: "Move/rename — source path ceases to exist"
      - command: "truncate"
        description: "File truncation"
      - command: "write_file"
        condition: "target_exists"
        description: "Overwrite existing file"
      - command: "sed"
        args_contain: ["-i"]
        description: "In-place file edit"
      - command: "chmod"
        description: "Permission change, audit only"
        vault: skip
        modify:
          clamp_permission: "755"
      - command: "chown"
        description: "Ownership change, audit only"
        vault: skip
      - command: "cp"
        condition: "target_exists"
        description: "Copy that overwrites existing target"
```

### 2. Update `README.md`

Add MODIFY to the verdict table:

```markdown
| Verdict | Meaning | Example |
|---|---|---|
| ALLOW | Action permitted, proceed | `cat file.txt` |
| DENY | Action blocked | `rm -rf /` |
| ESCALATE | Requires human approval | `curl https://api.example.com` |
| MODIFY | Action rewritten to safe form | `chmod 777` -> `chmod 755` |
```

Add MODIFY to the pipeline diagram (after "Verdict" step, before "Execute"):

```
... -> Verdict -> [MODIFY: rewrite args, re-evaluate] -> Execute/Deny
```

Add a "MODIFY Verdict" section under Features:

```markdown
### MODIFY Verdict (v0.4.0)

The gate can rewrite tool call parameters to make them policy-compliant
rather than blocking them outright.  Examples:

- `chmod 777 deploy.sh` -> `chmod 755 deploy.sh` (permission clamped)
- `rm -rf /workspace/data/` -> `rm -r /workspace/data/` (force flag stripped)

Five modify operations are supported: `clamp_permission`, `strip_flags`,
`require_flags`, `append_arg`, `max_depth`.  All operations are idempotent
and fail closed.

The proxy owns the reinvocation loop: after modification, the gate
re-evaluates the modified call.  One combined audit record captures
both original and modified parameters.
```

Update test count to ~428.

### 3. Update `ROADMAP.md`

Mark Phase 7 as completed:

```markdown
### Phase 7: MODIFY Decision (v0.4.0) ✅

Added the MODIFY verdict — the gate can rewrite tool call parameters
to make them policy-compliant rather than blocking outright.

- `Verdict.MODIFY` in gate evaluation pipeline
- Five modify operations: clamp_permission, strip_flags, require_flags,
  append_arg, max_depth
- Reinvocation loop in MCP proxy (depth cap = 1)
- Pattern-level `vault: skip` for permission/ownership changes
- `args_match` regex-based argument matching
- Combined audit records with original + modified parameters
- OPA backend modifications rule support
- ~115 new tests (total ~428)
```

### 4. Update `AARM_Alignment.md`

Update R4 status:

```markdown
### R4: Five Authorization Decisions

**Status:** ⚠️ Improved (4 of 5)

| Decision | Status | Implementation |
|---|---|---|
| ALLOW | ✅ | `Verdict.ALLOW` in gate.py |
| DENY | ✅ | `Verdict.DENY` in gate.py |
| ESCALATE | ✅ | `Verdict.ESCALATE` in gate.py |
| MODIFY | ✅ | `Verdict.MODIFY` with reinvocation loop |
| DEFER | ❌ | Not yet implemented (future phase) |
```

Update R5 to note dual-parameter receipts:

```markdown
### R5: Signed Receipts

**Status:** ⚠️ Improved

Audit records now capture both original and modified parameters for
MODIFY decisions.  Hash chain covers all fields including modification
data.  Pre-modification parameters are always preserved for forensic
review.
```

### 5. Update `COMPLIANCE.md`

Add new control mappings:

```markdown
| Control | Phase | Implementation |
|---|---|---|
| CM-3 (Change Control) | 7 | MODIFY verdict with audit trail of original + modified params |
| SI-10 (Information Input Validation) | 7 | Argument rewriting via modify operations |
| AU-12 (Audit Generation) | 7 | Combined audit records for MODIFY decisions |
```

---

## Verification

```bash
# Run ALL tests to confirm nothing broke
python -m pytest -x -q

# Verify default policy still loads
python -c "from agent_gate.policy_loader import load_policy; p = load_policy('policies/default.yaml', '.'); print(f'Policy loaded: {p.name}')"

# Expected: all ~428 tests pass, policy loads cleanly
```

---

## Commit

```
Phase 7.8: Documentation and default policy for MODIFY verdict

Modified: policies/default.yaml
- chmod and chown patterns gain vault: skip
- chmod gains modify: {clamp_permission: "755"}

Modified: README.md
- MODIFY verdict in pipeline diagram and verdict table
- MODIFY features section
- Updated test count

Modified: ROADMAP.md
- Phase 7 marked as completed

Modified: AARM_Alignment.md
- R4 status updated (4 of 5 decisions)
- R5 status updated (dual-parameter receipts)

Modified: COMPLIANCE.md
- New NIST control mappings for MODIFY
```
