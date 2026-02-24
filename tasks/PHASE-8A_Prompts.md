# Phase 8A Implementation Plan: Sub-agent Permission Inheritance (Revised)

**Date:** 2026-02-24
**Version target:** v0.4.1
**Supersedes:** First plan (Option 1 — structural bypass, not deterministic)

---

## 1. Architecture Decision

**Option 1 (env var injection) is a structural bypass, not an edge case risk.  It is rejected.**

Option 1 fails the deterministic requirement for two compounding reasons.  First: there is no PreToolUse hook on the Task tool in the current codebase (`settings_example.json`, `README.md`, and the hooks table all confirm coverage of Bash, Write, and Edit only).  With no Task hook, nobody trusted sets `AGENT_GATE_PARENT_SESSION` or `AGENT_GATE_DEPTH` before the sub-agent spawns.  Second: even if those vars were set, the agent could unset or overwrite them before the child hook reads them.  Any mechanism where the AGENT controls the input to the gate's depth and inheritance checks is not deterministic.  A prompt-injected sub-agent that reports `AGENT_GATE_DEPTH=0` bypasses the entire system with no detection.

**Selected approach: UUID token hybrid (Option 2 variant with cryptographic token).**

The design principle is: the gate writes the trust anchor, not the agent.  The agent can see the UUID that was written for it, but cannot forge its contents, because the manifest lives in agent-unreachable storage.

**Mechanism:**

1. A new `agent_gate_hook_task.py` registers as a `PreToolUse` hook on the Task tool.  It fires in the PARENT's security context before the sub-agent spawns.
2. The hook generates a UUID via `uuid.uuid4()` (Python standard library, no new dependencies), reads the current session's identity context, and writes a signed manifest to `~/.agent-gate/sessions/<uuid>.json`.
3. The sessions directory MUST be in `denied_paths`.  Phase 8A makes this automatic: when the `agents` section is present, `policy_loader.py` checks that a path covering `~/.agent-gate/sessions/` appears in `denied_paths` and raises `PolicyValidationError` if it does not.  This is a hard error, not a silent auto-add, because silently adding a path to denied_paths would obscure what the policy actually says.
4. The UUID is passed to the sub-agent as `AGENT_GATE_SESSION_TOKEN` in its environment.  The agent knows its own token but cannot reach the manifest it points to.
5. When the child gate initializes (on the sub-agent's first hook call), it reads `AGENT_GATE_SESSION_TOKEN`, looks up `~/.agent-gate/sessions/<token>.json`, loads inherited deny rules and depth from the manifest, and marks the manifest as claimed by renaming it to `<uuid>.claimed`.  Forging a UUID points to a nonexistent manifest and triggers the safe default (base policy, depth=0).

**Why this is trustworthy:**

The env var `AGENT_GATE_SESSION_TOKEN` is forgeable.  But a forged token is a lookup key only.  The policy values the gate enforces — inherited deny rules, depth — come exclusively from the manifest.  The manifest was written by the Task hook in the parent's security context before the sub-agent existed, in storage the agent cannot read, write, or delete.  Forging the token to point at a nonexistent manifest produces base policy enforcement, not elevated access.  There is no path from a forged token to reduced restriction.

**UNVERIFIED — requires live test before implementation proceeds:**

Two assumptions in this architecture have not been confirmed from any file in the codebase:

1. **Whether Claude Code fires `PreToolUse` for the Task tool.**  The existing `settings_example.json` only registers Bash, Write, and Edit matchers.  The Claude Code hook infrastructure supports tool-name-based matchers, but no test in this repo exercises a Task hook.  If PreToolUse does not fire for Task, the trust anchor is never written and the entire inheritance mechanism does not activate.

2. **Whether a PreToolUse hook on Task can inject `AGENT_GATE_SESSION_TOKEN` into the sub-agent's environment.**  The existing hooks communicate with Claude Code via exit code only.  Whether hook stdout output or a specially formatted response can modify the environment of the spawned sub-agent process is not confirmed.  If it cannot, the token delivery mechanism must change to a filesystem-based pending-slot approach (described in Honest Limitations, item 1).

**Implementation of Phase 8A must not proceed past the policy_loader and audit changes (Wave 1) until these two questions are answered by a live test.**

---

## 2. File Change Map

### `agent_gate/policy_loader.py`
**What changes:**

Add `self.agents_config = self._raw.get("agents", {})` in `Policy.__init__` after the identity fields.

Add a `_validate_agents(self)` method called from `_validate()` when the section is present.  Validation covers:
- `inheritance` must be one of `strict`, `permissive`, `additive`
- `subagent_overrides.max_depth` must be a positive integer when present
- `subagent_overrides.additional_deny` must be a list of strings when present, each entry in the format `"ToolName"` or `"ToolName(prefix:*)"` (prefix semantics only, documented in schema comment)
- `allowed_tools` is NOT a recognized field in Phase 8A.  If present, raise `PolicyValidationError` with the message: "agents.subagent_overrides.allowed_tools is not supported in this version.  See ROADMAP_v2.md Deferred section."

Add a sessions directory check inside `_validate_agents()`: when the `agents` section is present, verify that `~/.agent-gate/sessions/` (expanded) is covered by at least one entry in `denied_paths`.  Raise `PolicyValidationError` if not, with message: "agents section requires '~/.agent-gate/sessions/**' in envelope.denied_paths to protect session manifests from agent access."

The section is fully optional — no change to `REQUIRED_SECTIONS`.

**Complexity:** Medium.

**Dependencies:** None.  Runs in Wave 1.

---

### `agent_gate/audit.py`
**What changes:**

Add three Optional fields to the `AuditRecord` dataclass after `reinvocation_verdict`:

```python
# Sub-agent hierarchy fields (Phase 8A)
agent_depth: Optional[int] = None
parent_agent_id: Optional[str] = None
inherited_policy: Optional[bool] = None
```

Add the same three keyword arguments with `Optional` types and `None` defaults to `log_tool_call()`, passed through to the `AuditRecord` constructor.

No changes to `verify_chain()` or hash computation.  The `to_json()` `if v is not None` filter already handles new Optional fields correctly.

**Complexity:** Small.

**Dependencies:** None.  Runs in Wave 1 alongside policy_loader.

---

### `agent_gate/cli.py`
**What changes:**

Add `tree` subcommand.  New `cmd_tree(args)` function accepts a session ID and reads a JSONL log file.  Builds agent hierarchy by grouping records on `parent_agent_id` → `session_id` linkage.  Displays an indented tree with verdict counts per node.

New `tree_parser` with positional `session_id` and `--log` option (default: `~/.config/agent-gate/logs/gate.jsonl`).

Handles gracefully: log file not found, session not found in log, records missing agent hierarchy fields (pre-Phase-8A logs).

**Complexity:** Medium.

**Dependencies:** Logically requires gate.py to write the fields, but the command can be written against the expected schema and tested with fixture log data.  Runs in Wave 1.

---

### NEW FILE: `integrations/claude_code/agent_gate_hook_task.py`
**What this is:**

The trust anchor writer.  This hook fires on the Task tool's `PreToolUse` event, in the parent's security context, before the sub-agent spawns.  It is the only trustworthy writer of session manifests.

**What it does:**

1. Reads the current session's identity context (session_id, operator, role, depth) from env vars.  Reads the gate's agents config to determine what deny rules to inherit.
2. Loads the policy (using `load_policy`).  Read `agents_config = policy.agents_config`.
3. If the current depth would exceed `max_depth` when incremented, exits 2 (blocks the Task call) with a message: "Task blocked: sub-agent depth {current+1} would exceed max_depth {max_depth}."  This is where depth enforcement is actually deterministic — the Task never spawns.
4. Generates `uuid.uuid4()` as the session token.
5. Writes `~/.agent-gate/sessions/<uuid>.json` with the manifest schema.
6. Attempts to inject `AGENT_GATE_SESSION_TOKEN=<uuid>` into the sub-agent's environment.  **[See UNVERIFIED item 2 in Architecture Decision.]**  If injection is not possible via the hook stdout mechanism, falls back to writing a pending slot file that the child claims on first hook invocation.
7. Exits 0 (allows the Task to proceed).

**Manifest schema:**
```json
{
  "token": "<uuid>",
  "parent_session_id": "<parent_session_id>",
  "depth": "<parent_depth + 1>",
  "operator": "<operator>",
  "role": "<role>",
  "inherited_deny": ["Bash(rm:*)", "Bash(curl:*)"],
  "created_at": "<iso timestamp>",
  "expires_at": "<iso timestamp, default +60 min>",
  "claimed": false
}
```

**Complexity:** Medium.  The blocking logic (depth enforcement) is the most important part and must be correct.

**Dependencies:** None from the gate library except policy_loader (to read agents_config).  Can be implemented in Wave 2 after the UNVERIFIED questions are answered.

---

### `agent_gate/gate.py`
**What changes:**

1. Add `agent_depth: int = 0`, `parent_session_id: Optional[str] = None`, and `session_token: Optional[str] = None` to `Gate.__init__` signature.

2. Add a `_load_session_manifest(session_token)` helper that reads `~/.agent-gate/sessions/<token>.json`, validates the token is not expired and not yet claimed, loads `inherited_deny` and `depth` from it, and renames the file to `<token>.claimed`.  Returns the manifest dict or `None` on any failure (expired, missing, malformed).  On `None`, gate operates with base policy and depth=0 (safe default).

3. Call `_load_session_manifest` at `__init__` time when `session_token` is provided.  Store the resolved depth and deny rules on `self`.  Add a `_resolve_agents_config()` method parallel to `_resolve_rate_limits()`.

4. Add `agent_depth`, `parent_agent_id`, and `inherited_policy` fields to `GateDecision`.  Update `to_dict()` to include them.

5. In `evaluate()`, add two new steps after circuit breaker and before rate limits:
   - **Depth check:** If `self.agent_depth` exceeds `max_depth` from agents config, return hard deny.  (This should rarely trigger in practice, because the Task hook blocks the spawn at depth limit.  It is a defense-in-depth fallback.)
   - **Inherited deny check:** If `self.agent_depth > 0` and inheritance is not `permissive`, check tool call against `inherited_deny` patterns.  Prefix semantics only.

6. Update `_log_decision()` to include agent fields in the log entry dict.

**Complexity:** Medium.

**Dependencies:** policy_loader.py changes (Wave 1) must complete first.  Runs in Wave 2.

---

### `integrations/claude_code/agent_gate_hook.py`
**What changes:**

Add `SESSION_TOKEN = os.environ.get("AGENT_GATE_SESSION_TOKEN", None)`.  Pass it to `Gate(...)` as `session_token=SESSION_TOKEN`.  The gate reads the manifest internally.  No depth or deny-rule logic belongs in the hook.

**Complexity:** Small (two lines).

**Dependencies:** gate.py changes must complete first.  Runs in Wave 3.

---

### `integrations/claude_code/agent_gate_hook_write.py`
**What changes:**

Identical to the `agent_gate_hook.py` addition above.

**Complexity:** Small.

**Dependencies:** Same as agent_gate_hook.py.  Runs in Wave 3.

---

### `integrations/claude_code/settings_example.json`
**What changes:**

Add a Task matcher entry with a comment noting the UNVERIFIED status:

```json
{
  "matcher": "Task",
  "_comment": "UNVERIFIED: requires live test to confirm Claude Code fires PreToolUse for Task",
  "hooks": [
    {
      "type": "command",
      "command": "PYTHONPATH=~/projects/agent-gate python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook_task.py"
    }
  ]
}
```

**Complexity:** Trivial.

**Dependencies:** agent_gate_hook_task.py.  Runs in Wave 3.

---

## 3. New Files Required

### `integrations/claude_code/agent_gate_hook_task.py`
The trust anchor writer.  Described fully in File Change Map above.

### `tests/test_agent_inheritance.py`
All Phase 8A gate enforcement tests.  Policy validation tests (Wave 1), enforcement tests (Wave 2), and manifest lifecycle tests (Wave 2).  Follows the `TestEnvironment` pattern from `test_gate.py`.

### `tests/test_audit_inheritance.py`
Audit-specific unit tests for the three new `AuditRecord` fields and `log_tool_call()` additions.  Owned by Agent B.  Follows the pattern of `tests/test_audit_modify.py`.

---

## 4. Agent Breakdown

### Agent A: Policy Loader Extension

**Scope:** `agent_gate/policy_loader.py`, policy-validation section of `tests/test_agent_inheritance.py`.

**Dependencies:** None.  Wave 1.

**Prompt:**

> You are implementing Phase 8A of Agent Gate: Sub-agent Permission Inheritance.  Your scope is `agent_gate/policy_loader.py` and the policy-validation portion of `tests/test_agent_inheritance.py`.
>
> Read `/Users/hammer32/projects/agent-gate/agent_gate/policy_loader.py` before making any changes.
>
> **What to implement in policy_loader.py:**
>
> 1. In `Policy.__init__`, after `self.identity_roles = ...`, add:
>    `self.agents_config = self._raw.get("agents", {})`
>
> 2. In `Policy._validate()`, after the identity validation block, add:
>    ```python
>    if "agents" in self._raw:
>        self._validate_agents()
>    ```
>
> 3. Implement `_validate_agents(self)`.  It validates the following structure (all fields optional within the section; the section itself is optional):
>    ```yaml
>    agents:
>      inheritance: "strict"    # must be: strict | permissive | additive
>      subagent_overrides:
>        max_depth: 2            # positive integer
>        additional_deny:        # list of strings
>          - "Bash(rm:*)"        # prefix semantics: Bash commands starting with "rm"
>          - "Write"             # any Write tool call
>    ```
>    - `inheritance` not in `{"strict", "permissive", "additive"}` → `PolicyValidationError`
>    - `max_depth` not a positive integer → `PolicyValidationError`
>    - `additional_deny` not a list → `PolicyValidationError`
>    - `allowed_tools` present → `PolicyValidationError` with message: "agents.subagent_overrides.allowed_tools is not supported in this version.  See ROADMAP_v2.md Deferred section."
>
> 4. Inside `_validate_agents()`, add a sessions directory guard.  When the `agents` section is present, expand `~/.agent-gate/sessions/` to an absolute path.  Verify that at least one entry in `self._raw["envelope"]["denied_paths"]` covers that path (i.e., the denied path string, with trailing `**` stripped, is a prefix of the sessions directory path, or vice versa).  If not covered, raise `PolicyValidationError` with: "agents section requires '~/.agent-gate/sessions/**' in envelope.denied_paths to protect session manifests from agent access."
>
> **What to implement in tests/test_agent_inheritance.py:**
>
> Create the file.  Include a `TestEnvironment` class (reuse the pattern from `tests/test_gate.py`) that writes a policy YAML with an `agents` section and the required `~/.agent-gate/sessions/**` in denied_paths.  Write a `run_tests()` function with a `test()` inner helper that prints PASS/FAIL.
>
> Policy validation tests:
> - Valid `agents` section with all fields → loads without error
> - `inheritance` value not in allowed set → `PolicyValidationError`
> - `max_depth` is a string → `PolicyValidationError`
> - `additional_deny` is a string, not a list → `PolicyValidationError`
> - `allowed_tools` present → `PolicyValidationError` with "not supported in this version" in message
> - `agents` section absent → loads without error (backward compatibility)
> - `agents` section present but `~/.agent-gate/sessions/**` absent from denied_paths → `PolicyValidationError` with "session manifests" in message
>
> Add a `__main__` block: `if __name__ == "__main__": sys.exit(0 if run_tests() else 1)`
>
> **Constraints:**
> - Do not use sed for file editing.
> - Do not modify any file except `agent_gate/policy_loader.py` and `tests/test_agent_inheritance.py`.
> - Run: `python tests/test_agent_inheritance.py`.  All tests must pass before you finish.

**Can run in parallel with:** Agent B.

---

### Agent B: Audit Schema + CLI Tree

**Scope:** `agent_gate/audit.py`, `agent_gate/cli.py`, `tests/test_audit_inheritance.py` (new).

**Dependencies:** None.  Wave 1.

**Prompt:**

> You are implementing Phase 8A of Agent Gate: Sub-agent Permission Inheritance.  Your scope is `agent_gate/audit.py`, `agent_gate/cli.py`, and the new `tests/test_audit_inheritance.py`.  Read `audit.py` and `cli.py` before making any changes.
>
> **Part 1: audit.py**
>
> Add three Optional fields to the `AuditRecord` dataclass after `reinvocation_verdict`:
>
> ```python
> # Sub-agent hierarchy fields (Phase 8A)
> agent_depth: Optional[int] = None
> parent_agent_id: Optional[str] = None
> inherited_policy: Optional[bool] = None
> ```
>
> Add the same three keyword arguments to `log_tool_call()` with `Optional` types and `None` defaults, passed through to the `AuditRecord` constructor.  Place them after `reinvocation_verdict`.
>
> Do not change `verify_chain()`, `GENESIS_HASH`, or any hash computation.  The `to_json()` filter (`if v is not None`) handles new Optional fields correctly.
>
> **Part 2: cli.py**
>
> Add a `tree` subcommand.  Register it in `main()`:
>
> ```python
> tree_parser = subparsers.add_parser(
>     "tree", help="Show agent session hierarchy from audit log"
> )
> tree_parser.add_argument(
>     "session_id",
>     help="Root session ID to display",
> )
> tree_parser.add_argument(
>     "--log",
>     default=str(Path.home() / ".config" / "agent-gate" / "logs" / "gate.jsonl"),
>     help="Path to gate audit log",
> )
> ```
>
> Add `"tree": cmd_tree` to the `commands` dict.
>
> Implement `cmd_tree(args)`:
>
> 1. If `args.log` does not exist: print "Log file not found: {path}" and return.
> 2. Read all lines.  For each non-blank line that parses as JSON: collect records using the following **top-level flat fields** — `agent_id`, `parent_agent_id`, `agent_depth`, `verdict`, and `tool`.  These fields are written directly into each JSONL record at the top level by `gate.py`'s `_log_decision()` — they are NOT nested under an `identity` key or any other sub-object.  Skip records missing `agent_id` silently, with a counter.
> 3. Starting from `args.session_id`, build the tree recursively: root is records where `agent_id == args.session_id`, children are records where `parent_agent_id == args.session_id`, and so on transitively.
> 4. If no records found for the root session: print "Session '{session_id}' not found in log." and return.
> 5. Print indented tree:
>
>    ```
>    Session: <session_id>  depth=0
>      allow: 14  deny: 2  escalate: 1
>      └── Sub-agent: <child_id>  depth=1  inherited_policy=True
>            allow: 8  deny: 5
>    ```
>
> 6. At the bottom, print the count of records skipped due to missing `agent_id`.
>
> **Note on log field layout:** Every JSONL record in `gate.jsonl` is a flat dict.  Agent C's changes to `gate.py` write `agent_id` (from `decision.identity["agent_id"]`), `agent_depth`, and `parent_agent_id` as top-level keys directly into the log entry dict — the same level as `"verdict"`, `"tier"`, and `"policy_hash"`.  Do not look for a nested `"identity": {"agent_id": ...}` structure; it does not exist in the log.  Missing fields in older log entries (pre-Phase-8A) are handled gracefully.
>
> **Part 3: tests/test_audit_inheritance.py**
>
> Create this file.  Follow the pattern of the existing `tests/test_audit_modify.py` — use a temp file for the JSONL log, create an `AuditLogger`, call `log_tool_call()`, then read and parse the output to verify fields.
>
> Tests to write:
> - `log_tool_call()` with `agent_depth=1`, `parent_agent_id="session-abc"`, `inherited_policy=True` → record contains all three fields at the top level of the JSON output
> - `log_tool_call()` with no agent fields → record does NOT contain `agent_depth`, `parent_agent_id`, or `inherited_policy` keys (backward compatibility — `to_json()` omits None fields)
> - `log_tool_call()` with `agent_depth=0` → `agent_depth` key IS present with value 0 (0 is not None, so it serializes)
> - `AuditRecord` with all three fields set → `_content_for_hashing()` includes them, hash changes relative to a record without them
> - `verify_chain()` on a log containing records with agent hierarchy fields → chain is valid (hash chain is not broken by the new fields)
>
> Add a `__main__` block following the pattern from `tests/test_gate.py`.
>
> **Constraints:**
> - Do not use sed for file editing.
> - Do not modify any file except `agent_gate/audit.py`, `agent_gate/cli.py`, and `tests/test_audit_inheritance.py`.
> - Run: `python tests/test_audit_inheritance.py`.  All tests must pass before you finish.

**Can run in parallel with:** Agent A.

---

### Agent C: Gate Enforcement + Manifest Lookup

**Scope:** `agent_gate/gate.py`, enforcement and manifest tests in `tests/test_agent_inheritance.py`.

**Dependencies:** Agent A must complete (needs `Policy.agents_config`).  Wave 2.

**Prompt:**

> You are implementing Phase 8A of Agent Gate: Sub-agent Permission Inheritance.  Your scope is `agent_gate/gate.py` and the enforcement section of `tests/test_agent_inheritance.py`.
>
> Read `agent_gate/gate.py` and the existing `tests/test_agent_inheritance.py` (written by Agent A, contains policy validation tests) before making any changes.
>
> **Part 1: gate.py**
>
> **1a. Update `Gate.__init__` signature:**
>
> Add after `identity`:
> ```python
> agent_depth: int = 0,
> parent_session_id: Optional[str] = None,
> session_token: Optional[str] = None,
> ```
>
> Store on self, then call `self._agents_config = self._resolve_agents_config()`.
>
> If `session_token` is not None, call `self._load_session_manifest(session_token)` and update `self.agent_depth`, `self.parent_session_id`, and resolved `inherited_deny` rules from the manifest.  If manifest loading fails for any reason, log a warning and leave depth=0, no inherited rules (safe default).
>
> Update the `gate_initialized` log event to include `"agent_depth"` and `"parent_session_id"`.
>
> **1b. Implement `_resolve_agents_config(self) -> dict`:**
>
> Returns `self.policy.agents_config.copy()`.
>
> **1c. Implement `_load_session_manifest(self, token: str) -> Optional[dict]`:**
>
> ```python
> def _load_session_manifest(self, token: str) -> Optional[dict]:
>     """
>     Load and claim a session manifest written by the Task hook.
>
>     Returns the manifest dict if valid and unclaimed.
>     Returns None if the token is invalid, manifest is missing,
>     expired, or already claimed — gate operates with base policy.
>
>     Claiming: renames manifest to <token>.claimed to prevent replay.
>     """
>     from pathlib import Path
>     from datetime import datetime, timezone
>
>     sessions_dir = Path.home() / ".agent-gate" / "sessions"
>     manifest_path = sessions_dir / f"{token}.json"
>
>     if not manifest_path.exists():
>         self.logger.warning(json.dumps({
>             "event": "session_manifest_not_found",
>             "token": token,
>             "timestamp": datetime.now(timezone.utc).isoformat(),
>         }))
>         return None
>
>     try:
>         with open(manifest_path, "r") as f:
>             manifest = json.load(f)
>     except (IOError, json.JSONDecodeError) as e:
>         self.logger.warning(json.dumps({
>             "event": "session_manifest_read_error",
>             "token": token,
>             "error": str(e),
>             "timestamp": datetime.now(timezone.utc).isoformat(),
>         }))
>         return None
>
>     # Check expiry
>     expires_at = manifest.get("expires_at")
>     if expires_at:
>         try:
>             expiry = datetime.fromisoformat(expires_at)
>             if datetime.now(timezone.utc) > expiry:
>                 self.logger.warning(json.dumps({
>                     "event": "session_manifest_expired",
>                     "token": token,
>                     "expires_at": expires_at,
>                 }))
>                 return None
>         except ValueError:
>             pass  # malformed expiry — treat as valid, log nothing
>
>     # Claim: rename to prevent replay
>     try:
>         manifest_path.rename(manifest_path.with_suffix(".claimed"))
>     except OSError as e:
>         # If rename fails, do not load — prevents dual-claim on race
>         self.logger.warning(json.dumps({
>             "event": "session_manifest_claim_failed",
>             "token": token,
>             "error": str(e),
>         }))
>         return None
>
>     # Apply manifest values
>     self.agent_depth = manifest.get("depth", 0)
>     self.parent_session_id = manifest.get("parent_session_id")
>     self._inherited_deny = manifest.get("inherited_deny", [])
>
>     self.logger.info(json.dumps({
>         "event": "session_manifest_claimed",
>         "token": token,
>         "depth": self.agent_depth,
>         "parent_session_id": self.parent_session_id,
>         "inherited_deny_count": len(self._inherited_deny),
>         "timestamp": datetime.now(timezone.utc).isoformat(),
>     }))
>     return manifest
> ```
>
> Initialize `self._inherited_deny = []` in `__init__` before calling `_load_session_manifest`.
>
> **1d. Add `agent_depth`, `parent_agent_id`, `inherited_policy` to `GateDecision`:**
>
> After `modification_feedback`:
> ```python
> agent_depth: Optional[int] = None
> parent_agent_id: Optional[str] = None
> inherited_policy: Optional[bool] = None
> ```
>
> Update `to_dict()` to include these when set, using the same conditional pattern as `rate_status` and `identity`.
>
> **1e. Add two enforcement steps in `evaluate()`:**
>
> After circuit breaker, before tool rate limit.  Update the docstring step numbers to match.
>
> ```python
> # Step 2: Check agent depth limit (defense-in-depth; Task hook is primary).
> depth_result = self._check_agent_depth(tool_call)
> if depth_result is not None:
>     self._log_decision(depth_result)
>     return depth_result
>
> # Step 3: Check inherited deny rules from parent session manifest.
> inherited_result = self._check_inherited_deny(tool_call)
> if inherited_result is not None:
>     self._log_decision(inherited_result)
>     return inherited_result
> ```
>
> **1f. Implement `_check_agent_depth()`:**
>
> Only fires when `self.agent_depth > 0` (we are in a sub-agent).  Reads `max_depth` from `self._agents_config.get("subagent_overrides", {}).get("max_depth")`.  If depth exceeds max, returns a hard deny `GateDecision` with `verdict=Verdict.DENY`, reason describing depth and max, and `agent_depth`, `parent_agent_id`, `inherited_policy=True` set.  If `max_depth` is None or depth is within limit, returns None.
>
> **1g. Implement `_check_inherited_deny()`:**
>
> Only fires when `self.agent_depth > 0` and `self._agents_config.get("inheritance", "strict") != "permissive"` and `self._inherited_deny` is non-empty.
>
> Calls `_match_deny_pattern(raw_tool, command, self._inherited_deny)`.  If a pattern matches, returns hard deny with reason naming the matched rule and parent session.
>
> **1h. Implement `_match_deny_pattern()`:**
>
> Prefix semantics only.  Pattern format: `"ToolName"` or `"ToolName(prefix:*)"`.  Parse by splitting on `(`.  Map tool names: Bash → bash, Write → write_file, Read → read_file (case-insensitive, with underscore variants).  Return the first matched pattern string, or None if no match.
>
> Document with an explicit comment in the method:
> ```python
> # PATTERN SEMANTICS: Prefix matching only.
> # "Bash(rm:*)" matches any bash command whose first token starts with "rm".
> # This is NOT shell glob syntax — wildcards are not evaluated.
> # "Bash(rm -rf:*)" matches commands starting with "rm -rf".
> ```
>
> **1i. Update `_log_decision()`:**
>
> After `log_entry["policy_hash"] = self.policy.policy_hash`, add:
> ```python
> if self.agent_depth > 0:
>     log_entry["agent_depth"] = self.agent_depth
>     log_entry["parent_agent_id"] = self.parent_session_id
> ```
>
> **Part 2: tests/test_agent_inheritance.py enforcement tests**
>
> Append to the existing file from Agent A.  Add a `ManifestTestHelper` class that creates and removes temporary session manifests in a temp directory (parameterized path, not hardcoded to `~/.agent-gate/sessions`).  Create `Gate` instances directly with `session_token` kwargs pointing at the temp directory.  Do not use env vars in tests.
>
> Tests to add:
> - Gate with `session_token` pointing to valid manifest → depth and inherited_deny loaded from manifest
> - Gate with `session_token` pointing to nonexistent manifest → depth=0, no inherited rules (safe default)
> - Gate with `session_token` pointing to expired manifest → safe default
> - Gate with `session_token` for already-claimed manifest → safe default
> - Depth 3 with max_depth=2 → DENY, reason contains "depth"
> - Depth 1, inheritance=strict, additional_deny=["Bash(rm:*)"], command="rm file.txt" → DENY
> - Depth 1, inheritance=strict, additional_deny=["Bash(rm:*)"], command="cat file.txt" → ALLOW
> - Depth 1, inheritance=permissive → no inherited deny applied
> - Depth 0 → no inherited deny or depth check applied
> - GateDecision from a depth-denied call has `agent_depth`, `parent_agent_id`, `inherited_policy=True` in `to_dict()`
> - Manifest is renamed to `.claimed` after successful load (single-use token)
>
> **Constraints:**
> - Do not use sed for file editing.
> - Do not modify any file except `agent_gate/gate.py` and `tests/test_agent_inheritance.py`.
> - Run: `python tests/test_gate.py` (existing tests must still pass) and `python tests/test_agent_inheritance.py`.

**Can run in parallel with:** Agent B (different files).  Must run after Agent A.

---

### Agent D: Task Hook + Hook Updates + Settings

**Scope:** `integrations/claude_code/agent_gate_hook_task.py` (new), `integrations/claude_code/agent_gate_hook.py`, `integrations/claude_code/agent_gate_hook_write.py`, `integrations/claude_code/settings_example.json`.

**Dependencies:** Agent C must complete.  Wave 3.

**Prompt:**

> You are implementing Phase 8A of Agent Gate: Sub-agent Permission Inheritance.  Your scope is the Claude Code integration files.  Read all four files listed below before making any changes.
>
> Files to read first:
> - `/Users/hammer32/projects/agent-gate/integrations/claude_code/agent_gate_hook.py`
> - `/Users/hammer32/projects/agent-gate/integrations/claude_code/agent_gate_hook_write.py`
> - `/Users/hammer32/projects/agent-gate/integrations/claude_code/settings_example.json`
> - `/Users/hammer32/projects/agent-gate/integrations/claude_code/README.md`
>
> **Part 1: Create agent_gate_hook_task.py**
>
> This is a new PreToolUse hook for the Task tool.  It is the trust anchor writer for sub-agent session manifests.  It runs in the PARENT's security context before the sub-agent spawns.
>
> The file should follow the structure of `agent_gate_hook.py`.  Implement the following logic in `main()`:
>
> 1. Read stdin, parse JSON.  If `tool_name != "Task"`: exit 0.
>
> 2. Read configuration env vars (same pattern as existing hooks):
>    - `AGENT_GATE_POLICY`, `AGENT_GATE_WORKDIR`
>    - `AGENT_GATE_SESSION` (current parent session ID)
>    - `AGENT_GATE_DEPTH` (current depth, int, default 0, wrap in try/except ValueError)
>    - `AGENT_GATE_OPERATOR`, `AGENT_GATE_ROLE`
>
> 3. Load the policy (using `load_policy`).  Read `agents_config = policy.agents_config`.
>
> 4. **Depth enforcement (primary enforcement point):**
>    Read `max_depth = agents_config.get("subagent_overrides", {}).get("max_depth")`.
>    If `max_depth` is not None and `AGENT_GATE_DEPTH + 1 > max_depth`:
>    Print to stderr: `[AGENT GATE] Task blocked: spawning sub-agent would exceed max depth {max_depth}.  Current depth: {AGENT_GATE_DEPTH}.`
>    Exit 2.
>
> 5. **Generate session token:**
>    `import uuid; token = str(uuid.uuid4())`
>
> 6. **Build manifest:**
>    ```python
>    from datetime import datetime, timezone, timedelta
>    now = datetime.now(timezone.utc)
>    manifest = {
>        "token": token,
>        "parent_session_id": AGENT_GATE_SESSION,
>        "depth": AGENT_GATE_DEPTH + 1,
>        "operator": AGENT_GATE_OPERATOR,
>        "role": AGENT_GATE_ROLE,
>        "inherited_deny": agents_config.get(
>            "subagent_overrides", {}
>        ).get("additional_deny", []),
>        "created_at": now.isoformat(),
>        "expires_at": (now + timedelta(minutes=60)).isoformat(),
>        "claimed": False,
>    }
>    ```
>
> 7. **Write manifest to sessions directory:**
>    ```python
>    sessions_dir = Path.home() / ".agent-gate" / "sessions"
>    sessions_dir.mkdir(parents=True, exist_ok=True)
>    manifest_path = sessions_dir / f"{token}.json"
>    with open(manifest_path, "w") as f:
>        json.dump(manifest, f, indent=2)
>    ```
>    Wrap in try/except.  If write fails, print error to stderr and exit 2 (fail closed — if we cannot write the manifest, the sub-agent would run without inherited rules, which is unsafe).
>
> 8. **Token delivery:**
>    Attempt to write to stdout a JSON block that Claude Code may use to inject env vars.  The exact mechanism is UNVERIFIED — see the comment block at the top of the function.  For now, print the token to stdout as a structured note (it will appear as context in Claude's session), and also write the token to a well-known path for fallback discovery:
>    ```python
>    # UNVERIFIED: Whether Claude Code uses hook stdout to inject env vars
>    # into the sub-agent process.  This note serves as the fallback:
>    # the sub-agent's hook can scan ~/.agent-gate/sessions/ for the most
>    # recently created unclaimed manifest if AGENT_GATE_SESSION_TOKEN is absent.
>    print(json.dumps({
>        "note": "agent_gate_session_token",
>        "token": token,
>        "depth": AGENT_GATE_DEPTH + 1,
>    }))
>    ```
>
> 9. Exit 0.
>
> Add a prominent comment block at the top of the file above `main()`:
>
> ```python
> # UNVERIFIED ASSUMPTIONS — must be tested before relying on this hook:
> #
> # 1. Whether Claude Code fires PreToolUse for the Task tool.
> #    This hook is registered with matcher "Task" in settings_example.json.
> #    If PreToolUse does not fire for Task, this hook never runs and
> #    sub-agent session manifests are never written.
> #    Test: run Claude Code with a Task tool call and observe whether
> #    this script is invoked.
> #
> # 2. Whether AGENT_GATE_SESSION_TOKEN env var is visible to sub-agents.
> #    The hook writes the token to stdout and to the manifest file.
> #    If Claude Code does not propagate hook stdout as env vars to sub-agents,
> #    the child gate must discover its manifest via filesystem scan
> #    rather than token lookup.  See _load_session_manifest() in gate.py
> #    for the fallback path.
> ```
>
> **Part 2: Update agent_gate_hook.py and agent_gate_hook_write.py**
>
> In BOTH files, add after the existing `SESSION_ID` line:
>
> ```python
> SESSION_TOKEN = os.environ.get("AGENT_GATE_SESSION_TOKEN", None)
> ```
>
> In the `Gate(...)` constructor call in `main()`, add:
> ```python
> session_token=SESSION_TOKEN,
> ```
>
> **Part 3: Update settings_example.json**
>
> Add the Task matcher entry with a comment noting the UNVERIFIED status:
>
> ```json
> {
>   "matcher": "Task",
>   "_comment": "UNVERIFIED: requires live test to confirm Claude Code fires PreToolUse for Task",
>   "hooks": [
>     {
>       "type": "command",
>       "command": "PYTHONPATH=~/projects/agent-gate python3 ~/projects/agent-gate/integrations/claude_code/agent_gate_hook_task.py"
>     }
>   ]
> }
> ```
>
> **Constraints:**
> - Do not use sed for file editing.
> - Do not modify any file except the four listed.
> - The two existing hooks must remain independent scripts.  Do not introduce shared imports between them.

---

## 5. Sequencing and Parallelization

```
Wave 1 (parallel — no dependencies between them):
  Agent A — policy_loader.py + policy validation tests
  Agent B — audit.py + cli.py tree command

  *** HOLD POINT ***
  After Wave 1: answer the two UNVERIFIED questions via live test.
  Do not proceed to Wave 2 until confirmed.

Wave 2 (after Agent A + UNVERIFIED questions answered):
  Agent C — gate.py enforcement + manifest lifecycle tests
             (also appends to tests/test_agent_inheritance.py)

Wave 3 (after Agent C):
  Agent D — agent_gate_hook_task.py (new) + hook updates + settings_example.json
```

The hold point between Wave 1 and Wave 2 is not bureaucratic.  If `PreToolUse` does not fire for Task, the manifest is never written and `_load_session_manifest()` in Agent C must be designed around the filesystem-scan fallback instead of token lookup.  Building Agent C on the wrong assumption wastes the implementation.

---

## 6. Integration and Verification

**Phase 8A is complete when all of the following are true:**

1. `python tests/test_agent_inheritance.py` passes all tests (policy validation and enforcement).

2. `python tests/test_gate.py` passes all existing tests unchanged.

3. A policy YAML with no `agents` section loads successfully (backward compatibility).

4. A policy YAML with `agents` present but `~/.agent-gate/sessions/**` absent from `denied_paths` raises `PolicyValidationError`.

5. A `Gate` initialized with a `session_token` pointing at a valid manifest reads depth and inherited_deny from the manifest, not from env vars.

6. A `Gate` initialized with a forged token (no matching manifest) operates at depth=0 with base policy (safe default confirmed by test).

7. The manifest file is renamed to `.claimed` after a successful `Gate` initialization, preventing replay.

8. `agent-gate tree <session_id> --log <path>` runs against a fixture JSONL with agent hierarchy fields and prints the expected indented tree.

9. **Live test result documented:** Whether PreToolUse fires for Task, and whether `AGENT_GATE_SESSION_TOKEN` reaches the sub-agent's environment.  The live test result is committed to `integrations/claude_code/README.md` before Phase 8A is marked complete.

---

## 7. Honest Limitations

**Token delivery is UNVERIFIED until live-tested.**  If Claude Code does not propagate the session token to the sub-agent's environment, the child gate has no lookup key.  The fallback is filesystem scan: the child gate scans `~/.agent-gate/sessions/` for the most recently created unclaimed manifest, claims it, and loads it.  This fallback is correct for sequential Task spawning and is racy for parallel Task spawning.  Parallel Task spawning is a known gap; document it.

**Depth enforcement is defense-in-depth only when the Task hook fires.**  If the Task hook does not fire (UNVERIFIED), the only depth enforcement is in `gate.py`'s `_check_agent_depth()`, which only runs when the manifest was loaded and set `self.agent_depth` correctly.  Without a manifest, depth stays at 0 and depth limits do not apply.

**Prefix semantics, not glob semantics.**  `"Bash(rm:*)"` matches any bash command whose first token starts with `rm`.  `"Bash(rm -rf:*)"` matches commands starting with `rm -rf`.  This is string prefix matching.  The `*` in the pattern is a visual convention indicating "any suffix," not a shell glob that expands.  The policy schema comment and Known Limitations must use the word "prefix" and explicitly say it is not glob semantics.

**`allowed_tools` enforcement is deferred.**  The `allowed_tools` config key is rejected with a clear error in Phase 8A.  Enforcement requires the hook to know the Claude Code tool name (Task, Bash, Write, Edit) and map it to policy permissions before the gate's classification layer runs.  The architecture for this is straightforward but the implementation was removed from scope to avoid shipping a config option that silently does nothing.  See ROADMAP_v2.md Deferred section.

**MCP proxy gap remains.**  The MCP proxy path logs `AuditRecord` entries with the new fields (Agent B), but the gate enforcement logic only runs when `Gate` is constructed with a `session_token`.  The MCP proxy would need to read `AGENT_GATE_SESSION_TOKEN` and pass it to `Gate` to participate in inheritance enforcement.  Out of scope for Phase 8A.

**Manifest expiry is 60 minutes by default.**  A sub-agent that makes no Bash, Write, or Edit tool calls within 60 minutes of being spawned will fall back to base policy.  This is intentional — stale manifests should not accumulate indefinitely.  The expiry is configurable in the `agents` section and should be documented.

**Single-use tokens prevent replay but not pre-consumption.**  A sub-agent with OS-level read access to `~/.agent-gate/sessions/` before the gate claims the manifest could read the manifest content.  It cannot write to the directory (denied_paths enforcement), but it could learn the inherited deny rules before the gate loads them.  This is an observation capability, not a bypass capability — the gate still enforces whatever the manifest says.
