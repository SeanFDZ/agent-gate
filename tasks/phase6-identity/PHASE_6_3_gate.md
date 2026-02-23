# Phase 6.3: Gate — Identity Propagation & Role Overrides

**File:** `gate.py`
**Depends on:** Phase 6.1 (identity.py), Phase 6.2 (policy_loader.py)
**Parallel with:** Phase 6.4 (audit.py), Phase 6.5 (opa + rego)

---

## Before You Start

```bash
cat gate.py              # Full current Gate class
cat identity.py          # Phase 6.1 output
cat policy_loader.py     # Phase 6.2 output (identity section, get_role_overrides)
cat rate_tracker.py      # How rate limits are configured
cat test_gate.py         # Existing gate test patterns
cat test_gate_rates.py   # Rate limit test patterns
cat test_gate_feedback.py  # Feedback test patterns
```

---

## Context

The Gate needs three changes:

1. **Accept an optional `IdentityContext`** in `__init__` and store it.
2. **Apply role-based overrides** to rate limits and gate behavior when a role is present.
3. **Include identity in `GateDecision`** so downstream consumers (audit, agent feedback) can reference it.

Critical constraint: `Gate.__init__` currently takes `(policy_path, workdir, classifier_backend, opa_config)`.  Adding `identity` as an optional parameter preserves backward compatibility — existing code that doesn't pass identity gets `None` and behaves identically to v0.2.0.

---

## Deliverables

### `gate.py` Changes

```python
# Add import at top
from agent_gate.identity import IdentityContext, resolve_identity

class GateDecision:
    # Add field:
    identity: Optional[dict] = None  # IdentityContext.to_dict()

    # Update to_dict() to include identity if present
    def to_dict(self) -> dict:
        d = { ... existing ... }
        if self.identity:
            d["identity"] = self.identity
        return d


class Gate:
    def __init__(
        self,
        policy_path: str,
        workdir: str,
        classifier_backend: str = "python",
        opa_config: Optional[dict] = None,
        identity: Optional[IdentityContext] = None,
    ):
        self.policy = load_policy(policy_path, workdir)
        self.identity = identity

        # Apply role-based overrides to rate limits
        self._effective_rate_limits = self._resolve_rate_limits()

        self.classifier = self._create_classifier(
            classifier_backend, opa_config
        )
        self.vault = VaultManager(self.policy.vault_config)
        self.logger = self._setup_logger()
        self.rate_tracker = RateTracker(self._effective_rate_limits)

        # Apply role-based gate behavior overrides
        self._effective_gate_behavior = self._resolve_gate_behavior()

        self.logger.info(json.dumps({
            "event": "gate_initialized",
            "policy": self.policy.name,
            "workdir": workdir,
            "vault": self.policy.vault_config["path"],
            "classifier_backend": classifier_backend,
            "identity": (
                self.identity.to_dict() if self.identity else None
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

    def _resolve_rate_limits(self) -> dict:
        """
        Merge role-based rate limit overrides with base policy.

        If identity has a role and the policy defines overrides
        for that role, merge them.  Role overrides extend/replace
        base values, they don't remove them.
        """
        base = self.policy.rate_limits.copy()
        if not self.identity or not self.identity.role:
            return base

        overrides = self.policy.get_role_overrides(self.identity.role)
        if not overrides or "rate_limits" not in overrides:
            return base

        role_rl = overrides["rate_limits"]

        # Deep merge: role values override base values
        merged = self._deep_merge(base, role_rl)
        return merged

    def _resolve_gate_behavior(self) -> dict:
        """
        Merge role-based gate behavior overrides with base policy.

        If identity role has action behavior overrides (e.g.,
        admin gets network: allow), apply them.
        """
        base = dict(self.policy.gate_behavior)
        if not self.identity or not self.identity.role:
            return base

        overrides = self.policy.get_role_overrides(self.identity.role)
        if not overrides or "actions" not in overrides:
            return base

        for tier_name, tier_cfg in overrides["actions"].items():
            behavior = tier_cfg.get("behavior")
            if behavior:
                # Map tier_name to gate_behavior key
                behavior_key = f"on_{tier_name}"
                if behavior_key in base:
                    if isinstance(base[behavior_key], dict):
                        base[behavior_key] = dict(base[behavior_key])
                        base[behavior_key]["default"] = behavior
                    else:
                        base[behavior_key] = {"default": behavior}
        return base

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """
        Deep merge override into base.  Override values win.
        Both dicts are treated as immutable (copies are made).
        """
        result = {}
        for key in set(list(base.keys()) + list(override.keys())):
            if key in override and key in base:
                if isinstance(base[key], dict) and isinstance(override[key], dict):
                    result[key] = Gate._deep_merge(base[key], override[key])
                else:
                    result[key] = override[key]
            elif key in override:
                result[key] = override[key]
            else:
                result[key] = base[key]
        return result

    def evaluate(self, tool_call: dict) -> GateDecision:
        # Existing flow unchanged.
        # Only addition: every GateDecision gets identity attached.
        # After building decision, before returning:
        #   decision.identity = self.identity.to_dict() if self.identity else None

        # In _handle_network: use self._effective_gate_behavior
        # instead of self.policy.gate_behavior

    def _handle_network(self, tool_call, classification):
        # Change: use self._effective_gate_behavior.get("on_network", {})
        # instead of self.policy.gate_behavior.get("on_network", {})

    def _handle_unclassified(self, tool_call, classification):
        # Change: use self._effective_gate_behavior.get("on_unclassified", {})
        # instead of self.policy.gate_behavior.get("on_unclassified", {})
```

---

## Test Cases

### File: `test_gate_identity.py` (NEW)

```
# --- Backward Compatibility ---

test_gate_no_identity_works
    Gate(policy_path, workdir) with no identity param
    → gate.identity is None
    → evaluate() works normally

test_gate_none_identity_explicit
    Gate(policy_path, workdir, identity=None)
    → identical to no identity

# --- Identity Propagation ---

test_decision_includes_identity
    identity = IdentityContext(operator="sean", role="admin")
    gate = Gate(policy_path, workdir, identity=identity)
    decision = gate.evaluate(read_only_tool_call)
    → decision.identity == {"operator": "sean", "role": "admin"}

test_decision_identity_none_when_no_identity
    gate = Gate(policy_path, workdir)
    decision = gate.evaluate(read_only_tool_call)
    → decision.identity is None

test_decision_to_dict_includes_identity
    identity = IdentityContext(operator="sean")
    gate = Gate(..., identity=identity)
    d = gate.evaluate(tool_call).to_dict()
    → "identity" in d and d["identity"]["operator"] == "sean"

# --- Role-Based Rate Limit Overrides ---

test_admin_role_gets_higher_rate_limit
    Use policy_with_identity.yaml
    identity = IdentityContext(role="admin")
    gate = Gate(..., identity=identity)
    → gate._effective_rate_limits["global"]["max_calls"] == 500

test_restricted_role_gets_lower_rate_limit
    Use policy_with_identity.yaml
    identity = IdentityContext(role="restricted")
    gate = Gate(..., identity=identity)
    → gate._effective_rate_limits["global"]["max_calls"] == 50

test_unknown_role_gets_base_rate_limits
    Use policy_with_identity.yaml
    identity = IdentityContext(role="unknown")
    gate = Gate(..., identity=identity)
    → rate limits identical to base policy

test_no_role_gets_base_rate_limits
    Use policy_with_identity.yaml
    identity = IdentityContext(operator="sean")  # no role
    gate = Gate(..., identity=identity)
    → rate limits identical to base policy

# --- Role-Based Gate Behavior Overrides ---

test_admin_network_allowed
    Use policy_with_identity.yaml
    identity = IdentityContext(role="admin")
    gate = Gate(..., identity=identity)
    decision = gate.evaluate(curl_tool_call)
    → decision.verdict == Verdict.ALLOW

test_default_network_escalated
    Use policy_with_identity.yaml (no identity)
    gate = Gate(policy_path, workdir)
    decision = gate.evaluate(curl_tool_call)
    → decision.verdict == Verdict.ESCALATE

# --- Deep Merge ---

test_deep_merge_basic
    Gate._deep_merge({"a": 1}, {"b": 2})
    → {"a": 1, "b": 2}

test_deep_merge_override
    Gate._deep_merge({"a": 1}, {"a": 2})
    → {"a": 2}

test_deep_merge_nested
    Gate._deep_merge(
        {"a": {"x": 1, "y": 2}},
        {"a": {"y": 3, "z": 4}},
    )
    → {"a": {"x": 1, "y": 3, "z": 4}}

# --- Init Logging ---

test_init_log_includes_identity
    (Verify the gate_initialized log entry includes identity dict)
```

---

## Verification

```bash
python -m pytest test_gate_identity.py -v
python -m pytest -x -q
# Expected: all existing + ~15 new pass
```

---

## Commit

```
Phase 6.3: Gate identity propagation and role overrides

- Gate.__init__ accepts optional IdentityContext
- Role-based rate limit overrides via _resolve_rate_limits()
- Role-based gate behavior overrides via _resolve_gate_behavior()
- GateDecision.identity field for downstream propagation
- _deep_merge() utility for nested dict overlay
- 15 new tests in test_gate_identity.py
- All existing tests pass (backward compatible)
```
