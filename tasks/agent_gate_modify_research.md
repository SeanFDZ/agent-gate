# AGENT GATE
## Research Brief: MODIFY Decision Patterns
### Phase 7 Implementation Research

*Prepared: February 2026  |  Document Version: 1.0*

---

## Executive Summary

This document synthesizes findings from five mature systems that implement parameter rewriting at an interception layer: the AARM specification, Kubernetes mutating admission webhooks, OPA Gatekeeper, ProxySQL, and ModSecurity.  The research was conducted to inform Agent Gate's Phase 7 MODIFY verdict implementation.

Five key takeaways should shape the design:

**1.  Mutate first, then re-validate — always.**  Every mature system applies mutations before running validation.  In Kubernetes, the mutating webhook phase runs before the validating webhook phase.  In Gatekeeper, the Assign/AssignMetadata mutators fire before Constraint evaluation.  Agent Gate's MODIFY verdict must pass the rewritten call back through the full gate pipeline, not skip classification.  A modification that produces a call that would otherwise be denied is a policy violation.

**2.  Log both — original and modified — always.**  ProxySQL logs both the original digest and the rewritten digest in stats_mysql_query_digest.  Kubernetes audit annotations record the original request and the patch at both Metadata and Request audit levels.  AARM R5 requires tamper-evident receipts.  Agent Gate's audit records must capture the original parameters and the rewritten parameters as separate fields.  Losing the original destroys the forensic trail.

**3.  Fail closed when modification fails.**  When a Kubernetes webhook errors with `failurePolicy: Fail`, the request is rejected.  When a ProxySQL rewrite rule's regex is invalid, the rule is not applied and an error is logged.  The safe default is to deny the action if modification cannot be applied cleanly.  Silently passing through the original unmodified parameters after a modification failure would allow the action Agent Gate intended to constrain.

**4.  Rules should be declarative, not procedural.**  ProxySQL's query rules use `match_pattern` + `replace_pattern` (regex substitution).  Gatekeeper's Assign CRD uses a declarative YAML path-and-value schema with `pathTests` conditions.  Kubernetes MutatingAdmissionPolicies use CEL expressions.  None require procedural code to express common modifications.  Agent Gate's modification rules should be expressible in YAML, with procedural escapes reserved for complex cases.

**5.  Idempotency is not optional.**  Kubernetes good-practice guidance explicitly requires that mutating webhooks be idempotent, because `reinvocationPolicy: IfNeeded` can cause a webhook to run more than once on the same object.  An Agent Gate MODIFY rule that is not idempotent could accumulate side effects if the gate is invoked multiple times on retried or replayed tool calls.  Every modification operation (clamp, strip, append) must be safe to apply twice.

---

## 1.  AARM R4 — Five Authorization Decisions

### 1.1  The Specification's Definition of MODIFY

AARM R4 (a MUST requirement) specifies that a conformant system must implement all five authorization decisions: ALLOW, DENY, MODIFY, STEP_UP, and DEFER.  The AARM homepage at https://aarm.dev defines the five decisions as follows:

| Decision | AARM Definition |
|---|---|
| ALLOW | Action proceeds as submitted. |
| DENY | Action blocked with reason and escalation path. |
| MODIFY | Action parameters altered to conform to policy before forwarding. |
| STEP_UP | Action paused pending human approval (Agent Gate equivalent: ESCALATE). |
| DEFER | Action suspended pending additional context. |

The spec gives the following concrete example for MODIFY: a query submitted as `SELECT * FROM users` is rewritten to `SELECT * FROM users LIMIT 100` rather than being denied outright.  This "allow with guardrails" posture is described as preferable where a denial would block legitimate work that could proceed safely in a constrained form.

### 1.2  MODIFY and Receipts (R5)

AARM R5 requires tamper-evident receipts that cryptographically bind action, context, decision, and outcome.  The specification does not explicitly state whether the receipt binds the original or modified parameters — this is a gap.  However, the forensic purpose of receipts implies both must be present.  A receipt that only captures the modified parameters cannot reconstruct what the agent actually requested.  A receipt that only captures the original cannot verify what was actually forwarded to the tool.

Recommended interpretation: Agent Gate receipts for MODIFY decisions should bind both the original parameters and the modified parameters, with the modification rule identifier that produced the delta.  This preserves full forensic reconstruction.

### 1.3  MODIFY and Identity (R6)

AARM R6 (currently the largest gap in Agent Gate) requires identity binding at five levels: human, service, agent, session, and role/privilege scope.  The spec implies that modification rules should be identity-scoped, meaning different agents or roles might have different modification rules applied.  For example, a developer agent might have `SELECT *` queries clamped to `LIMIT 1000`, while a reporting agent has them clamped to `LIMIT 10000`.

Phase 7 does not need to solve full R6, but the MODIFY rule schema should be designed to accept an optional identity scope (role) so that Phase 6's identity work can be wired in without schema changes.

### 1.4  AARM Conformance Implication

Agent Gate currently implements ALLOW, DENY, and ESCALATE (partial STEP_UP equivalent).  Adding MODIFY moves R4 from "Partial" to "Improved" but does not reach full R4 conformance, because DEFER remains unimplemented.  This is an honest assessment for the AARM alignment document.

---

## 2.  Kubernetes Mutating Admission Webhooks

### 2.1  How Mutation Rules Are Defined

Kubernetes mutating admission webhooks are HTTP services configured via `MutatingWebhookConfiguration` resources.  Rules are expressed as match criteria (`apiGroups`, `apiVersions`, `resources`, `operations`) paired with a client configuration pointing to the webhook server.  The webhook server receives an `AdmissionReview` JSON object and returns an `AdmissionReview` response containing a JSON Patch (RFC 6902) array describing the mutations to apply.

As of Kubernetes v1.34, `MutatingAdmissionPolicy` resources allow mutations to be expressed as CEL expressions directly in the cluster configuration, without deploying a webhook server.  CEL expressions operate on the request object and return an `ApplyConfiguration` patch or `JSONPatch` operations.  This declarative form is closer to what Agent Gate needs.

### 2.2  Ordering and Composition

The Kubernetes documentation explicitly warns that mutating webhooks do not run in a guaranteed order.  Multiple factors can change when a specific webhook is called.  This has two implications for Agent Gate: first, if multiple MODIFY rules apply to the same tool call, their execution order must be explicitly defined (by rule priority or by applying them in sequence within a single handler).  Second, webhooks that depend on the output of other webhooks must use `reinvocationPolicy: IfNeeded`, which causes the webhook to be re-invoked after other plugins have run.

### 2.3  Failure Modes

`failurePolicy: Fail` (the default) causes the API server to reject the request if the webhook errors or times out.  `failurePolicy: Ignore` causes the request to proceed without mutation.  For security-critical mutations (stripping `-f` from `rm`, clamping `chmod` permissions), `failurePolicy: Fail` is the correct choice.  Kubernetes good practice guidance recommends using `Ignore` with a validating webhook backstop for non-critical defaults, and `Fail` for security enforcement.  This is the same dual-layer pattern Agent Gate should use: MODIFY failures deny the action.

### 2.4  Audit Logging

Kubernetes records webhook invocations in the audit log.  At Metadata audit level, the annotation `mutation.webhook.admission.k8s.io/round_{round_idx}_index_{order_idx}` indicates whether a mutation occurred.  At Request audit level, the annotation `patch.webhook.admission.k8s.io/round_{round_idx}_index_{order_idx}` records the actual JSON Patch applied.  This means Kubernetes logs: (1) that a mutation webhook was invoked, (2) the specific patch it applied.  The pre-mutation object is the original request captured in the audit record.  Agent Gate's audit field design should follow the same pattern: `pre_modification_params` and `post_modification_params` as separate fields in the audit JSONL record.

### 2.5  Reinvocation Policy

If a mutating webhook modifies an object, built-in mutating admission plugins are re-run.  Mutating webhooks can specify `reinvocationPolicy: IfNeeded` to indicate they should be re-invoked if another plugin has modified the object since the webhook's initial invocation.  This is what makes the mutate-then-validate pattern work: the full pipeline sees the final state, not intermediate states.

Agent Gate implication: after applying a MODIFY verdict, the modified tool call must be re-classified through the full gate pipeline.  The reinvocation guard is: if the second classification also returns MODIFY with the same rule, skip (idempotency).  If it returns DENY, block the original action.  If it returns ALLOW, proceed.

---

## 3.  OPA Gatekeeper Mutation Framework

### 3.1  Mutation CRDs

Gatekeeper's mutation system introduces four mutation-specific Custom Resource Definitions:

| CRD | Purpose | Scope |
|---|---|---|
| AssignMetadata | Modifies labels and annotations only. | More restricted — metadata only |
| Assign | Modifies any field outside metadata. | Full spec access |
| ModifySet | Adds or removes items from a list (treated as a set). | List fields (e.g., container args) |
| AssignImage | Modifies components of a container image string. | Image fields only |

Each CRD has three sections: extent of changes (`applyTo` — which resources are mutated, by group/version/kind and optional namespace/label selectors), location (the dot-notation path to the field being modified), and parameters (the value to assign and optional `pathTests` conditions).

### 3.2  Rego vs. Declarative YAML for Mutations

This is an important design signal: Gatekeeper's mutations are entirely declarative YAML.  Rego is used for validation (ConstraintTemplates), not for mutation.  The Gatekeeper GitHub issue tracker contains community requests for Rego-based mutations, but the project has not implemented them.  The reason is intentional: declarative mutations are easier to audit, test, and reason about than procedural Rego.  A mutation expressed as "set `spec.containers[name:foo].securityContext.privileged` to false" is immediately comprehensible.  A mutation expressed as Rego logic is not.

Agent Gate implication: MODIFY rules in the policy YAML should be declarative operations (set, clamp, strip, append, prepend), not procedural logic.  The rule author should not need to write Python or Rego to express common safety modifications.

### 3.3  pathTests — Conditional Mutation

Gatekeeper's Assign CRD supports `pathTests` conditions that gate whether a mutation applies.  For example:

```yaml
pathTests:
  - subPath: "spec.containers[name: foo]"
    condition: MustExist
  - subPath: "spec.containers[name: foo].securityContext.capabilities"
    condition: MustNotExist
```

The mutation only applies if the first path exists and the second does not.  This is equivalent to Agent Gate needing conditional modification: "strip the `-f` flag from `rm` args, but only if `-rf` is present."  The `pathTests` pattern should inform how Agent Gate expresses preconditions on MODIFY rules.

### 3.4  Mutation Order and Composition

Gatekeeper does not guarantee order across multiple Assign/AssignMetadata resources.  Within a single mutation CRD, operations are applied in the order they appear.  For Agent Gate, this means: if multiple MODIFY rules match the same tool call, they must be applied in a deterministic order (e.g., by rule_id, analogous to ProxySQL's rule ordering).

### 3.5  Mutate Then Validate

Gatekeeper explicitly separates the mutation phase from the validation phase.  Mutations are applied by the mutating webhook first.  Constraints (validation) evaluate the post-mutation state.  A resource that would fail validation pre-mutation is not blocked if the mutation brings it into compliance.  Conversely, a mutation that produces a non-compliant state will be caught by the validating webhook.  This is the pattern Agent Gate needs: apply MODIFY rules, then run the full gate classification on the modified parameters.

---

## 4.  ProxySQL Query Rewriting

### 4.1  Rule Syntax

ProxySQL stores query rules in the `mysql_query_rules` table.  Each rule has:

| Field | Purpose |
|---|---|
| rule_id | Numeric identifier.  Rules are evaluated in ascending rule_id order. |
| active | 1 = enabled, 0 = disabled.  Inactive rules are not evaluated. |
| match_pattern | POSIX regex matched against the full original query text.  Must match for replace_pattern to apply. |
| replace_pattern | Regex replacement string with capture group back-references (`\1`, `\2`, etc.). |
| match_digest | Matched against the query digest (parameterized form).  Used for routing only, not rewriting. |
| apply | 1 = stop processing further rules after this rule matches.  0 = continue. |

The key distinction: `match_pattern` targets the literal query text (required for rewriting).  `match_digest` targets the normalized digest form and can only route, not rewrite.  Agent Gate's parallel: the match criterion must target the actual argument values, not a normalized digest, in order to perform parameter rewriting.

### 4.2  Common Rewrite Patterns

**Limit injection:** Append `LIMIT N` to SELECT queries missing a LIMIT clause.  Match against the full query, replace with the captured query plus the appended limit.

**Parameter clamping:** Replace a specific argument value with a constrained value.  Analogous to `chmod 777` → `chmod 755`.

**Redaction:** Replace sensitive field references.  Example: `SELECT (.*)ssn(.*) FROM users` → `SELECT \1"REDACTED"\2 FROM users`.

**Flag stripping:** Remove specific argument flags from a command string.  Analogous to `rm -rf` → `rm -r`.

### 4.3  Failure Handling

If the `match_pattern` regex itself is invalid (malformed regex), ProxySQL logs an error and the rule is not applied.  The query passes through unmodified.  This is effectively "fail open" for individual rule errors — the query proceeds.  Shopify's engineering blog documents a dry-run mode they developed for ProxySQL to preview rule effects before activation, addressing the risk of unintended consequences at scale.

Agent Gate difference: ProxySQL's fail-open behavior is acceptable for performance optimization rules (worst case: a suboptimal query runs).  For security enforcement (worst case: an unconstrained destructive action executes), fail-closed is required.

### 4.4  Dual Logging

ProxySQL's `stats_mysql_query_digest` table records statistics for each distinct query digest.  After rewriting, both the original digest and the rewritten digest appear as separate entries.  This means: the original query's execution count is recorded, and the rewritten query's execution count is also recorded separately.  Both are visible to the DBA.  Agent Gate should follow the same pattern: the audit record for a MODIFY verdict should include both the original tool call parameters and the modified parameters.

### 4.5  Performance

ProxySQL's rewrite matching is synchronous, regex-based, and in-process.  The overhead is negligible for the query volume ProxySQL handles (hundreds of thousands of queries per second).  For Agent Gate, the analogous operation — matching a tool name and argument string against a set of MODIFY rules — is similarly low-cost and should not add measurable latency to the gate's evaluation path.

---

## 5.  ModSecurity WAF — Transform Actions

### 5.1  What "Transform" Means in WAF Context

ModSecurity's transform concept is importantly different from what Agent Gate needs.  ModSecurity transforms are input normalization functions applied to a copy of the data before matching — they do not modify the actual request or response.  The original input is never changed.  This is used for anti-evasion: for example, applying `t:lowercase` before a regex match ensures that SQL injection patterns are detected regardless of case.

This is the key distinction: ModSecurity transforms are for detection, not enforcement.  They normalize inputs to improve rule matching accuracy.  The actual request forwarded to the application is unchanged.  This is not what Agent Gate's MODIFY verdict needs.

### 5.2  Transform Pipeline

Multiple transformation functions can be chained in a single rule, forming a transformation pipeline.  They execute in declaration order.  Example:

```
SecRule ARGS "@rx <script>"
  "id:1001,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny"
```

The pipeline is: strip existing transforms → decode URL encoding → decode HTML entities → lowercase → match.  The input is not modified — each transform creates a new working copy.  The matching happens against the final transformed copy.  The request forwarded to the application still contains the original, untransformed data.

### 5.3  The Closer Analog — setvar

The closer ModSecurity analog to Agent Gate's MODIFY is the `setvar` action combined with a transformation that changes collection variables.  ModSecurity can set, delete, and modify variables (including request parameters) using non-disruptive `setvar` actions.  However, this is rarely used in practice because modifying request parameters in a WAF introduces fragility and is considered an anti-pattern.  WAF best practice is to block rather than modify.

### 5.4  Logging Pre- and Post-State

ModSecurity does not natively log the pre-transform state of a variable separately from the post-transform state, because transforms do not change the request.  For Agent Gate's MODIFY verdict (which does change the forwarded parameters), explicit logging of both states is required and is not something ModSecurity's design can inform.  The ProxySQL dual-digest pattern and Kubernetes audit patch annotations are the better reference models for Agent Gate logging.

### 5.5  What ModSecurity Confirms

Despite its transform semantics being different from Agent Gate's needs, ModSecurity confirms two design principles.  First: transformation pipelines should be ordered and expressed declaratively (as a sequence of named operations, not procedural code).  Second: the audit trail should always capture the pre-operation state.  Agent Gate needs to capture both.

---

## 6.  Common Patterns Across All Systems

Five design decisions that all five systems agree on:

| Pattern | Evidence Across Systems |
|---|---|
| Mutate first, then re-validate. | Kubernetes: mutating webhooks run before validating webhooks.  Gatekeeper: Assign CRDs evaluated before ConstraintTemplates.  ProxySQL: rewrite happens before query is forwarded.  Agent Gate must re-run the full gate on the modified call. |
| Log both original and modified. | ProxySQL: both digests in stats_mysql_query_digest.  Kubernetes: original object and patch in audit.  AARM R5: receipts bind original action and outcome.  Agent Gate audit records must include pre_modification_params and post_modification_params. |
| Fail closed when modification fails. | Kubernetes: `failurePolicy: Fail` for security-critical webhooks.  ProxySQL: invalid regex = rule skipped (fail open for optimization, but Agent Gate needs fail closed for security enforcement).  Gatekeeper: failed mutation blocks the request. |
| Rules are declarative, not procedural. | Gatekeeper: Assign CRD is pure YAML.  ProxySQL: match_pattern + replace_pattern in a table row.  ModSecurity: named transform functions (urlDecodeUni, lowercase) not Rego or Python.  Procedural escapes exist but are used sparingly. |
| Idempotency is required. | Kubernetes good practice: every mutating webhook must be idempotent.  ProxySQL: apply=1 stops rule chain after first match (prevents double-application).  Gatekeeper: pathTests with MustNotExist prevents re-mutation.  Agent Gate MODIFY rules must produce the same result when applied to already-modified parameters. |

---

## 7.  Design Implications for Agent Gate

### 7.1  Should Modification Rules Be Declarative YAML or Procedural?

Declarative YAML for common operations, with a procedural escape hatch.

The evidence is clear: every mature system uses declarative rules as the primary authoring surface.  The YAML schema should express named operations with parameters:

```yaml
actions:
  destructive:
    patterns:
      - tool: "bash"
        args_match: "-rf"
        modify:
          strip_arg_flags: ["-f"]          # Remove force flag
      - tool: "database_query"
        args_match: "^SELECT.*"
        modify:
          append_if_absent: "LIMIT 100"   # Add LIMIT if not present
      - tool: "bash"
        args_match: "chmod \\d{3,4}"
        modify:
          clamp_permission: "755"         # Maximum allowed permission
```

The procedural escape should be a Python function hook for cases not expressible in declarative form.  This is consistent with how ProxySQL users extend beyond what the rule table can express.

### 7.2  Should the Modified Result Be Re-Evaluated?

Yes, always.  The Kubernetes reinvocation pattern and the Gatekeeper mutate-then-validate pattern both confirm this.  The re-evaluation serves two purposes: it catches modifications that produce a result that would still be denied by the gate, and it verifies that the modification was idempotent (a second pass produces no further changes).

Implementation note: the re-evaluation should pass a flag indicating it is a reinvocation, so the gate does not emit a second audit record for the same action.  The audit record should be a single entry with both the original and modified parameters, verdict MODIFY, and the modification rule that fired.

### 7.3  How Should Modification Compose With Identity/Role Overrides?

Agent Gate Phase 6 (Identity Binding, currently in March 2026 planning) will introduce role-based policy differentiation.  MODIFY rules should be scoped by role at the policy YAML level, following Gatekeeper's namespace/label scoping pattern.  The schema extension is:

```yaml
roles:
  developer:
    modify_rules:
      - tool: "database_query"
        modify:
          append_if_absent: "LIMIT 1000"
  reporting:
    modify_rules:
      - tool: "database_query"
        modify:
          append_if_absent: "LIMIT 10000"
```

Phase 7 does not require this to be implemented, but the schema must reserve the `role` key to avoid a breaking change when Phase 6 wires in identity.

### 7.4  What Is the Right Failure Mode?

Fail closed.  When a MODIFY rule matches a tool call but the modification cannot be applied (malformed rule, argument not found in the expected position, regex substitution failure), the gate should deny the action with a clear error indicating which modification rule failed and why.  The agent feedback should include: original call, intended modification, failure reason, and the escalation path.

This is the opposite of ProxySQL's default (fail open for performance optimization rules).  The difference is consequence: a ProxySQL rewrite that fails means a suboptimal query runs.  An Agent Gate modification that fails means a potentially unsafe action runs unconstrained.

### 7.5  Should Audit Records Capture Original, Modified, or Both?

Both, always.  The audit record for a MODIFY verdict should include:

- `verdict: MODIFY`
- `original_tool_call: { tool_name, original_parameters }`
- `modified_tool_call: { tool_name, modified_parameters }`
- `modification_rule: { rule_id, rule_description, operations_applied }`
- `reinvocation_result: { verdict_on_modified_call }`
- `timestamp, session_id, policy_hash, record_hash` (existing fields)

This is consistent with AARM R5 (tamper-evident receipts binding action, context, decision, and outcome), Kubernetes Request audit level (patch annotation), and ProxySQL dual-digest logging.

### 7.6  Agent Feedback on MODIFY

Agent Gate already returns structured denial feedback on DENY verdicts.  MODIFY verdicts should return a structured modification notice:

```json
{
  "verdict": "MODIFY",
  "original_call": { "tool": "bash", "args": "chmod 777 deploy.sh" },
  "modified_call": { "tool": "bash", "args": "chmod 755 deploy.sh" },
  "reason": "Permission clamped to 755 per policy rule chmod-clamp-prod",
  "policy_rule": "chmod-clamp-prod"
}
```

The agent receives this feedback and the modified call is forwarded to the server.  The agent is informed of the modification so it can update its reasoning context.  This is consistent with Agent Gate's existing feedback-on-denial design philosophy: the gate does not just say "no," it explains what happened and what will proceed.

---

## 8.  Items Not Found / Uncertainty Flags

- **AARM spec — MODIFY and receipts interaction:** The AARM specification at aarm.dev does not explicitly define whether R5 receipts must bind original parameters, modified parameters, or both for MODIFY verdicts.  The interpretation in Section 1.2 is inferred from the forensic purpose of receipts, not stated in the spec.  Recommend raising this with Herman Errico as a spec clarification request.

- **AARM spec — MODIFY and identity interaction:** Similarly, the spec does not explicitly define whether modification rules must be identity-scoped.  The R6 requirement (identity binding) implies that all authorization decisions, including MODIFY, should be identity-aware, but the spec does not say "modification rules must vary by identity."  This is an inference.

- **Gatekeeper mutation order:** The Gatekeeper documentation states that mutation order is not guaranteed across multiple Assign resources.  The community has raised issues about this.  There is no documented mechanism to force a specific order across Assign CRDs.  This is relevant to Agent Gate only if multiple MODIFY rules match the same tool call — the YAML policy order should be treated as authoritative.

- **ProxySQL and original query in audit:** ProxySQL logs both digests in `stats_mysql_query_digest`, but the full original query text is not separately preserved in an audit log designed for forensic recovery.  The stats table is a performance telemetry surface, not an audit trail.  Agent Gate's MODIFY audit must explicitly preserve the original parameters in the audit record.

- **ModSecurity request parameter mutation:** The research did not find production examples of ModSecurity being used to actually rewrite forwarded request parameters (as opposed to normalizing inputs for detection).  This is consistent with WAF best-practice guidance that discourages parameter rewriting in WAFs.  ModSecurity is not a good implementation reference for Agent Gate's MODIFY mechanics.

---

*Agent Gate — Phase 7 MODIFY Research Brief  |  For internal use  |  February 2026*
