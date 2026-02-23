"""
Agent Gate — Rate Tracker

Sliding window counter rate limiting and three-state circuit breaker
for controlling agent operational tempo.

Design decisions:
  - Sliding window counter (not log) for O(1) memory per counter.
  - Three-state circuit breaker (CLOSED/OPEN/HALF_OPEN) with
    automatic recovery via HALF_OPEN probing.
  - All state is in-memory.  Resets on gate restart, which is
    itself a reasonable circuit breaker reset.
  - Pure tracking module with no gate/classifier dependency.
    The gate calls us; we don't call the gate.
"""

import time
from enum import Enum
from typing import Dict, Optional


class SlidingWindowCounter:
    """
    Memory-efficient sliding window counter for rate limiting.

    Uses two fixed windows (previous and current) to compute a
    weighted count.  This prevents boundary bursts while using
    O(1) memory per counter.

    Algorithm:
      1. Maintain counts for the current and previous fixed windows.
      2. When the current window expires, rotate: previous = current,
         current = new empty window.
      3. Effective count = (previous_count * weight) + current_count,
         where weight = 1 - (elapsed_in_current / window_seconds).
      4. Compare effective count against max_calls.
    """

    def __init__(self, max_calls: int, window_seconds: int):
        self.max_calls = max_calls
        self.window_seconds = max(window_seconds, 1)
        self._current_count = 0
        self._previous_count = 0
        self._current_start = time.monotonic()

    def _rotate_if_needed(self, now: float) -> None:
        """Rotate windows if the current window has expired."""
        elapsed = now - self._current_start
        if elapsed >= self.window_seconds:
            windows_passed = int(elapsed / self.window_seconds)
            if windows_passed >= 2:
                # Both windows are stale, reset everything.
                self._previous_count = 0
                self._current_count = 0
            else:
                # One window passed, rotate.
                self._previous_count = self._current_count
                self._current_count = 0
            self._current_start += windows_passed * self.window_seconds

    def record(self) -> None:
        """Record a call at the current time."""
        now = time.monotonic()
        self._rotate_if_needed(now)
        self._current_count += 1

    def effective_count(self) -> float:
        """
        Compute the weighted count across previous and current windows.

        The weight of the previous window decreases linearly as time
        progresses through the current window.  At the window boundary,
        100% of the previous window counts; at the end of the current
        window, 0% counts.
        """
        now = time.monotonic()
        self._rotate_if_needed(now)
        elapsed_in_current = now - self._current_start
        weight = 1.0 - (elapsed_in_current / self.window_seconds)
        weight = max(0.0, min(1.0, weight))
        return (self._previous_count * weight) + self._current_count

    def is_exceeded(self) -> bool:
        """Check if the rate limit has been reached or exceeded."""
        return self.effective_count() >= self.max_calls

    def remaining(self) -> float:
        """Calls remaining before the limit is reached."""
        return max(0.0, self.max_calls - self.effective_count())

    def seconds_until_reset(self) -> float:
        """Time in seconds until the current window rotates."""
        now = time.monotonic()
        self._rotate_if_needed(now)
        elapsed = now - self._current_start
        return max(0.0, self.window_seconds - elapsed)

    def reset(self) -> None:
        """Clear all state."""
        self._current_count = 0
        self._previous_count = 0
        self._current_start = time.monotonic()


class BreakerState(Enum):
    """The three states of a circuit breaker."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Three-state circuit breaker for agent operational safety.

    States: CLOSED (normal) -> OPEN (tripped) -> HALF_OPEN (testing) -> CLOSED

    In CLOSED state, all calls flow through and outcomes are tracked.
    If the failure rate exceeds the threshold within the sliding window,
    the breaker transitions to OPEN.

    In OPEN state, calls are restricted based on on_trip policy.
    After wait_duration_open_seconds, transitions to HALF_OPEN.

    In HALF_OPEN state, a limited number of probe calls are allowed.
    If all succeed, transitions to CLOSED.  If any fail, returns to OPEN.
    """

    def __init__(self, config: dict):
        self._enabled = config.get("enabled", False)
        self._sliding_window_size = config.get("sliding_window_size", 20)
        self._minimum_calls = config.get("minimum_calls", 10)
        self._failure_rate_threshold = config.get(
            "failure_rate_threshold", 0.50
        )
        self._wait_duration_seconds = config.get(
            "wait_duration_open_seconds", 30
        )
        self._permitted_half_open = config.get(
            "permitted_calls_half_open", 3
        )
        self._on_trip = config.get("on_trip", "read_only")
        self._message = config.get(
            "message", "Circuit breaker tripped."
        )

        self._state = BreakerState.CLOSED
        # Ring buffer of booleans: True = success, False = failure.
        self._outcomes = []  # type: list
        self._opened_at = 0.0
        self._half_open_successes = 0
        self._half_open_calls = 0

    @property
    def state(self) -> BreakerState:
        """
        Current breaker state, with automatic OPEN -> HALF_OPEN transition.

        When the breaker is OPEN and the wait duration has elapsed,
        it automatically transitions to HALF_OPEN for probing.
        """
        if not self._enabled:
            return BreakerState.CLOSED

        if self._state == BreakerState.OPEN:
            now = time.monotonic()
            if now - self._opened_at >= self._wait_duration_seconds:
                self._state = BreakerState.HALF_OPEN
                self._half_open_successes = 0
                self._half_open_calls = 0

        return self._state

    def record_success(self) -> None:
        """Record a successful call outcome."""
        if not self._enabled:
            return

        current = self.state

        if current == BreakerState.HALF_OPEN:
            self._half_open_successes += 1
            self._half_open_calls += 1
            if self._half_open_successes >= self._permitted_half_open:
                # All probes succeeded, close the breaker.
                self._state = BreakerState.CLOSED
                self._outcomes.clear()
                self._half_open_successes = 0
                self._half_open_calls = 0
        elif current == BreakerState.CLOSED:
            self._outcomes.append(True)
            if len(self._outcomes) > self._sliding_window_size:
                self._outcomes = self._outcomes[-self._sliding_window_size:]

    def record_failure(self) -> None:
        """Record a failed call outcome."""
        if not self._enabled:
            return

        current = self.state

        if current == BreakerState.HALF_OPEN:
            # Any failure in half-open sends back to OPEN.
            self._state = BreakerState.OPEN
            self._opened_at = time.monotonic()
            self._half_open_successes = 0
            self._half_open_calls = 0
        elif current == BreakerState.CLOSED:
            self._outcomes.append(False)
            if len(self._outcomes) > self._sliding_window_size:
                self._outcomes = self._outcomes[-self._sliding_window_size:]

            # Check if we should trip the breaker.
            if len(self._outcomes) >= self._minimum_calls:
                failures = sum(1 for o in self._outcomes if not o)
                rate = failures / len(self._outcomes)
                if rate >= self._failure_rate_threshold:
                    self._state = BreakerState.OPEN
                    self._opened_at = time.monotonic()

    def should_allow(self, tier: str) -> bool:
        """
        Returns True if the action should proceed.

        In OPEN state, behavior depends on on_trip:
          - "deny_all": nothing passes
          - "read_only": only read_only tier passes
          - "escalate": nothing passes (caller returns escalation info)
        In HALF_OPEN, limited probe calls pass.
        In CLOSED, everything passes.
        """
        if not self._enabled:
            return True

        current = self.state

        if current == BreakerState.CLOSED:
            return True

        if current == BreakerState.OPEN:
            if self._on_trip == "read_only":
                return tier == "read_only"
            # "deny_all" and "escalate" both block here;
            # the caller distinguishes deny from escalate via on_trip.
            return False

        if current == BreakerState.HALF_OPEN:
            return self._half_open_calls < self._permitted_half_open

        return True

    def seconds_until_half_open(self) -> float:
        """Seconds remaining until the breaker transitions to HALF_OPEN."""
        if self._state != BreakerState.OPEN:
            return 0.0
        elapsed = time.monotonic() - self._opened_at
        return max(0.0, self._wait_duration_seconds - elapsed)

    def trip_reason(self) -> Optional[str]:
        """Return the trip message if the breaker is OPEN or HALF_OPEN."""
        if not self._enabled:
            return None

        current = self.state
        if current in (BreakerState.OPEN, BreakerState.HALF_OPEN):
            return self._message
        return None

    def reset(self) -> None:
        """Reset the breaker to CLOSED with a clean slate."""
        self._state = BreakerState.CLOSED
        self._outcomes.clear()
        self._half_open_successes = 0
        self._half_open_calls = 0


class RateTracker:
    """
    Tracks tool call rates for rate limiting and circuit breaker evaluation.

    Maintains in-memory sliding window counters per tool, per tier,
    and globally.  Computes rate context for OPA input or audit logging.

    If rate_config is empty or None, all methods are no-ops.  This
    ensures backward compatibility when rate_limits is absent from
    the YAML policy.
    """

    def __init__(self, rate_config: Optional[dict] = None):
        self._config = rate_config or {}
        self._enabled = bool(self._config)

        if not self._enabled:
            self._tool_counters = {}  # type: Dict[str, SlidingWindowCounter]
            self._tier_counters = {}  # type: Dict[str, SlidingWindowCounter]
            self._global_counter = None  # type: Optional[SlidingWindowCounter]
            self._breaker = CircuitBreaker({"enabled": False})
            self._backoff_config = {}  # type: dict
            self._consecutive_violations = {}  # type: Dict[str, int]
            return

        # Per-tool counters from config.
        self._tool_counters = {}  # type: Dict[str, SlidingWindowCounter]
        tools_config = self._config.get("tools", {})
        for tool_name, cfg in tools_config.items():
            self._tool_counters[tool_name] = SlidingWindowCounter(
                max_calls=cfg.get("max_calls", 100),
                window_seconds=cfg.get("window_seconds", 60),
            )

        # Per-tier default counters.
        self._tier_counters = {}  # type: Dict[str, SlidingWindowCounter]
        tier_config = self._config.get("tier_defaults", {})
        for tier_name, cfg in tier_config.items():
            self._tier_counters[tier_name] = SlidingWindowCounter(
                max_calls=cfg.get("max_calls", 100),
                window_seconds=cfg.get("window_seconds", 60),
            )

        # Global counter.
        global_cfg = self._config.get("global", {})
        if global_cfg:
            self._global_counter = (
                SlidingWindowCounter(
                    max_calls=global_cfg.get("max_calls", 200),
                    window_seconds=global_cfg.get("window_seconds", 60),
                )
            )  # type: Optional[SlidingWindowCounter]
        else:
            self._global_counter = None

        # Circuit breaker.
        breaker_cfg = self._config.get("circuit_breaker", {})
        self._breaker = CircuitBreaker(breaker_cfg)

        # Backoff tracking: tool_name -> consecutive violation count.
        self._backoff_config = self._config.get("backoff", {})
        self._consecutive_violations = {}  # type: Dict[str, int]

    def record_call(self, tool_name: str, tier: str) -> None:
        """Record that a tool call was made.  Updates all relevant counters."""
        if not self._enabled:
            return

        if tool_name in self._tool_counters:
            self._tool_counters[tool_name].record()

        if tier in self._tier_counters:
            self._tier_counters[tier].record()

        if self._global_counter:
            self._global_counter.record()

    def record_outcome(
        self,
        tool_name: str,
        success: bool,
        duration_ms: float = 0.0,
    ) -> None:
        """
        Record the outcome of a tool call for circuit breaker evaluation.

        A successful outcome also resets the backoff counter for the tool.
        """
        if not self._enabled:
            return

        if success:
            self._breaker.record_success()
            # Reset backoff on success.
            if tool_name in self._consecutive_violations:
                del self._consecutive_violations[tool_name]
        else:
            self._breaker.record_failure()

    def check_rate_limit(
        self, tool_name: str, tier: str
    ) -> Optional[dict]:
        """
        Check if the next tool call should be rate limited.

        Returns None if allowed, or a dict with denial info.
        Checks in priority order: circuit breaker, tool, tier, global.
        """
        if not self._enabled:
            return None

        # 1. Circuit breaker (highest priority).
        if not self._breaker.should_allow(tier):
            reason = self._breaker.trip_reason()
            breaker_cfg = self._config.get("circuit_breaker", {})
            return {
                "source": "circuit_breaker",
                "on_exceed": breaker_cfg.get("on_trip", "read_only"),
                "message": reason or "Circuit breaker tripped.",
                "rate_remaining": 0,
                "rate_limit": 0,
                "reset_seconds": self._breaker.seconds_until_half_open(),
                "window_seconds": 0,
                "current_count": 0,
                "breaker_state": self._breaker.state.value,
            }

        # 2. Per-tool limit.
        if tool_name in self._tool_counters:
            counter = self._tool_counters[tool_name]
            if counter.is_exceeded():
                tools_cfg = self._config.get("tools", {}).get(
                    tool_name, {}
                )
                result = {
                    "source": "tool",
                    "on_exceed": tools_cfg.get("on_exceed", "deny"),
                    "message": tools_cfg.get(
                        "message",
                        f"{tool_name} rate limit exceeded.  "
                        f"Max {counter.max_calls} calls per "
                        f"{counter.window_seconds}s.",
                    ),
                    "rate_remaining": counter.remaining(),
                    "rate_limit": counter.max_calls,
                    "reset_seconds": counter.seconds_until_reset(),
                    "window_seconds": counter.window_seconds,
                    "current_count": counter.effective_count(),
                    "breaker_state": self._breaker.state.value,
                }
                self._track_backoff(tool_name, result)
                return result

        # 3. Per-tier default.
        if tier in self._tier_counters:
            counter = self._tier_counters[tier]
            if counter.is_exceeded():
                tier_cfg = self._config.get("tier_defaults", {}).get(
                    tier, {}
                )
                result = {
                    "source": "tier",
                    "on_exceed": tier_cfg.get("on_exceed", "deny"),
                    "message": tier_cfg.get(
                        "message",
                        f"{tier} tier rate limit exceeded.  "
                        f"Max {counter.max_calls} calls per "
                        f"{counter.window_seconds}s.",
                    ),
                    "rate_remaining": counter.remaining(),
                    "rate_limit": counter.max_calls,
                    "reset_seconds": counter.seconds_until_reset(),
                    "window_seconds": counter.window_seconds,
                    "current_count": counter.effective_count(),
                    "breaker_state": self._breaker.state.value,
                }
                self._track_backoff(tool_name, result)
                return result

        # 4. Global limit.
        if self._global_counter and self._global_counter.is_exceeded():
            global_cfg = self._config.get("global", {})
            result = {
                "source": "global",
                "on_exceed": global_cfg.get("on_exceed", "read_only"),
                "message": global_cfg.get(
                    "message",
                    f"Global rate limit exceeded.  "
                    f"Max {self._global_counter.max_calls} calls per "
                    f"{self._global_counter.window_seconds}s.",
                ),
                "rate_remaining": self._global_counter.remaining(),
                "rate_limit": self._global_counter.max_calls,
                "reset_seconds": (
                    self._global_counter.seconds_until_reset()
                ),
                "window_seconds": self._global_counter.window_seconds,
                "current_count": (
                    self._global_counter.effective_count()
                ),
                "breaker_state": self._breaker.state.value,
            }
            self._track_backoff(tool_name, result)
            return result

        return None

    def _track_backoff(self, tool_name: str, result: dict) -> None:
        """Add exponential backoff timing to a rate limit result."""
        if not self._backoff_config.get("enabled", False):
            return

        violations = self._consecutive_violations.get(tool_name, 0) + 1
        self._consecutive_violations[tool_name] = violations

        initial = self._backoff_config.get("initial_wait_seconds", 5)
        multiplier = self._backoff_config.get("multiplier", 2.0)
        max_wait = self._backoff_config.get("max_wait_seconds", 300)

        wait = initial * (multiplier ** (violations - 1))
        wait = min(wait, max_wait)
        result["retry_after_seconds"] = wait

    def get_rate_context(self) -> dict:
        """
        Build the rate_context dict for OPA input or audit logging.

        Returns an empty dict when rate limiting is disabled.
        """
        if not self._enabled:
            return {}

        tool_counts = {}
        for name, counter in self._tool_counters.items():
            tool_counts[name] = {
                "count": counter.effective_count(),
                "window_seconds": counter.window_seconds,
            }

        tier_counts = {}
        for name, counter in self._tier_counters.items():
            tier_counts[name] = {
                "count": counter.effective_count(),
                "window_seconds": counter.window_seconds,
            }

        context = {
            "tool_counts": tool_counts,
            "tier_counts": tier_counts,
            "global_count": {
                "count": (
                    self._global_counter.effective_count()
                    if self._global_counter
                    else 0
                ),
                "window_seconds": (
                    self._global_counter.window_seconds
                    if self._global_counter
                    else 60
                ),
            },
            "circuit_breaker": {
                "state": self._breaker.state.value,
            },
        }
        return context

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        """The underlying circuit breaker instance."""
        return self._breaker

    @property
    def breaker_state(self) -> BreakerState:
        """Current circuit breaker state."""
        return self._breaker.state
