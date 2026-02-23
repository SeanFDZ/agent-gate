"""
Tests for Agent Gate rate tracker.

Covers sliding window counter, three-state circuit breaker,
and the RateTracker orchestrator.
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.rate_tracker import (
    SlidingWindowCounter,
    BreakerState,
    CircuitBreaker,
    RateTracker,
)


class TestSlidingWindowCounter(unittest.TestCase):
    """Test SlidingWindowCounter basics and sliding window algorithm."""

    @patch("agent_gate.rate_tracker.time")
    def test_record_and_count(self, mock_time):
        """Record calls and verify effective count."""
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=10, window_seconds=60)

        for _ in range(5):
            counter.record()

        self.assertAlmostEqual(counter.effective_count(), 5.0, places=1)
        self.assertFalse(counter.is_exceeded())

    @patch("agent_gate.rate_tracker.time")
    def test_exceeded_at_limit(self, mock_time):
        """Counter reports exceeded when count reaches max_calls."""
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=5, window_seconds=60)

        for _ in range(5):
            counter.record()

        self.assertTrue(counter.is_exceeded())

    @patch("agent_gate.rate_tracker.time")
    def test_window_rotation(self, mock_time):
        """Old calls expire after one full window rotation."""
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=10, window_seconds=60)

        # Record 8 calls at t=0.
        for _ in range(8):
            counter.record()

        # Move to t=60 (start of new window).
        # Previous window has 8 calls, current has 0.
        # Weight = 1 - (0/60) = 1.0, so effective = 8*1 + 0 = 8.
        mock_time.monotonic.return_value = 60.0
        self.assertAlmostEqual(counter.effective_count(), 8.0, places=1)

        # Move to t=90 (halfway through new window).
        # Weight = 1 - (30/60) = 0.5, so effective = 8*0.5 + 0 = 4.
        mock_time.monotonic.return_value = 90.0
        self.assertAlmostEqual(counter.effective_count(), 4.0, places=1)

        # Move to t=120 (two full windows later).
        # Both windows are stale, effective = 0.
        mock_time.monotonic.return_value = 120.0
        self.assertAlmostEqual(counter.effective_count(), 0.0, places=1)

    @patch("agent_gate.rate_tracker.time")
    def test_boundary_burst_prevention(self, mock_time):
        """
        Weighted count prevents a burst at the window boundary.

        If 9 calls happen at the end of window 1 and 9 at the start
        of window 2, the effective count should be close to 18,
        not reset to 9.
        """
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=20, window_seconds=60)

        # Record 9 calls near end of first window (t=59).
        mock_time.monotonic.return_value = 59.0
        for _ in range(9):
            counter.record()

        # Move to t=61 (just past the boundary).
        # Previous window had 9 calls.
        # Weight = 1 - (1/60) ~ 0.983, so effective ~ 9*0.983 + 0 ~ 8.85.
        mock_time.monotonic.return_value = 61.0

        # Now record 9 more calls.
        for _ in range(9):
            counter.record()

        # effective ~ 9 * (1 - 1/60) + 9 ~ 8.85 + 9 = 17.85
        count = counter.effective_count()
        self.assertGreater(count, 17.0)
        self.assertLess(count, 18.0)

    @patch("agent_gate.rate_tracker.time")
    def test_remaining_accuracy(self, mock_time):
        """Remaining count should be max_calls minus effective_count."""
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=10, window_seconds=60)

        for _ in range(3):
            counter.record()

        remaining = counter.remaining()
        self.assertAlmostEqual(remaining, 7.0, places=1)

    @patch("agent_gate.rate_tracker.time")
    def test_seconds_until_reset(self, mock_time):
        """Reset timer should reflect time remaining in current window."""
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=10, window_seconds=60)
        counter.record()

        mock_time.monotonic.return_value = 45.0
        reset = counter.seconds_until_reset()
        self.assertAlmostEqual(reset, 15.0, places=1)

    @patch("agent_gate.rate_tracker.time")
    def test_reset_clears_state(self, mock_time):
        """Reset should clear all counts."""
        mock_time.monotonic.return_value = 0.0
        counter = SlidingWindowCounter(max_calls=10, window_seconds=60)

        for _ in range(10):
            counter.record()

        self.assertTrue(counter.is_exceeded())

        counter.reset()
        self.assertFalse(counter.is_exceeded())
        self.assertAlmostEqual(counter.effective_count(), 0.0, places=1)


class TestCircuitBreaker(unittest.TestCase):
    """Test three-state circuit breaker transitions."""

    def _make_config(self, **overrides):
        """Build a circuit breaker config with sensible test defaults."""
        config = {
            "enabled": True,
            "sliding_window_size": 10,
            "minimum_calls": 5,
            "failure_rate_threshold": 0.50,
            "wait_duration_open_seconds": 10,
            "permitted_calls_half_open": 3,
            "on_trip": "read_only",
            "message": "Test breaker tripped.",
        }
        config.update(overrides)
        return config

    def test_starts_closed(self):
        """Breaker starts in CLOSED state."""
        breaker = CircuitBreaker(self._make_config())
        self.assertEqual(breaker.state, BreakerState.CLOSED)

    def test_closed_to_open(self):
        """Breaker trips to OPEN when failure rate exceeds threshold."""
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            failure_rate_threshold=0.50,
        ))

        # 5 failures out of 5 = 100% failure rate.
        for _ in range(5):
            breaker.record_failure()

        self.assertEqual(breaker.state, BreakerState.OPEN)

    @patch("agent_gate.rate_tracker.time")
    def test_open_to_half_open(self, mock_time):
        """After wait duration, OPEN transitions to HALF_OPEN."""
        mock_time.monotonic.return_value = 0.0
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            wait_duration_open_seconds=10,
        ))

        # Trip the breaker.
        for _ in range(5):
            breaker.record_failure()

        self.assertEqual(breaker.state, BreakerState.OPEN)

        # Not enough time elapsed.
        mock_time.monotonic.return_value = 5.0
        self.assertEqual(breaker.state, BreakerState.OPEN)

        # Wait duration elapsed.
        mock_time.monotonic.return_value = 10.0
        self.assertEqual(breaker.state, BreakerState.HALF_OPEN)

    @patch("agent_gate.rate_tracker.time")
    def test_half_open_to_closed(self, mock_time):
        """Successful probes in HALF_OPEN transition to CLOSED."""
        mock_time.monotonic.return_value = 0.0
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            wait_duration_open_seconds=10,
            permitted_calls_half_open=3,
        ))

        # Trip the breaker.
        for _ in range(5):
            breaker.record_failure()

        # Wait for half-open.
        mock_time.monotonic.return_value = 10.0
        self.assertEqual(breaker.state, BreakerState.HALF_OPEN)

        # 3 successful probes.
        for _ in range(3):
            breaker.record_success()

        self.assertEqual(breaker.state, BreakerState.CLOSED)

    @patch("agent_gate.rate_tracker.time")
    def test_half_open_to_open(self, mock_time):
        """A failure in HALF_OPEN sends breaker back to OPEN."""
        mock_time.monotonic.return_value = 0.0
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            wait_duration_open_seconds=10,
            permitted_calls_half_open=3,
        ))

        # Trip the breaker.
        for _ in range(5):
            breaker.record_failure()

        # Wait for half-open.
        mock_time.monotonic.return_value = 10.0
        self.assertEqual(breaker.state, BreakerState.HALF_OPEN)

        # One success, then a failure.
        breaker.record_success()
        breaker.record_failure()

        self.assertEqual(breaker.state, BreakerState.OPEN)

    def test_minimum_calls_respected(self):
        """
        Breaker should not trip if below minimum_calls, even with
        100% failure rate.
        """
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=10,
            failure_rate_threshold=0.50,
        ))

        # 4 failures out of 4, but minimum is 10.
        for _ in range(4):
            breaker.record_failure()

        self.assertEqual(breaker.state, BreakerState.CLOSED)

    def test_should_allow_closed(self):
        """In CLOSED state, all tiers are allowed."""
        breaker = CircuitBreaker(self._make_config())
        self.assertTrue(breaker.should_allow("destructive"))
        self.assertTrue(breaker.should_allow("read_only"))

    def test_should_allow_open_read_only_trip(self):
        """In OPEN with on_trip=read_only, only read_only passes."""
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            on_trip="read_only",
        ))
        for _ in range(5):
            breaker.record_failure()

        self.assertTrue(breaker.should_allow("read_only"))
        self.assertFalse(breaker.should_allow("destructive"))
        self.assertFalse(breaker.should_allow("network"))

    def test_should_allow_open_deny_all(self):
        """In OPEN with on_trip=deny_all, nothing passes."""
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            on_trip="deny_all",
        ))
        for _ in range(5):
            breaker.record_failure()

        self.assertFalse(breaker.should_allow("read_only"))
        self.assertFalse(breaker.should_allow("destructive"))

    def test_trip_reason(self):
        """Trip reason returns message when breaker is tripped."""
        breaker = CircuitBreaker(self._make_config(
            minimum_calls=5,
            message="Custom trip message.",
        ))
        self.assertIsNone(breaker.trip_reason())

        for _ in range(5):
            breaker.record_failure()

        self.assertEqual(breaker.trip_reason(), "Custom trip message.")

    def test_reset(self):
        """Reset returns breaker to CLOSED with clean state."""
        breaker = CircuitBreaker(self._make_config(minimum_calls=5))
        for _ in range(5):
            breaker.record_failure()

        self.assertEqual(breaker.state, BreakerState.OPEN)
        breaker.reset()
        self.assertEqual(breaker.state, BreakerState.CLOSED)

    def test_disabled_breaker_always_closed(self):
        """A disabled breaker is always CLOSED and always allows."""
        breaker = CircuitBreaker({"enabled": False})
        for _ in range(100):
            breaker.record_failure()

        self.assertEqual(breaker.state, BreakerState.CLOSED)
        self.assertTrue(breaker.should_allow("destructive"))
        self.assertIsNone(breaker.trip_reason())


class TestRateTracker(unittest.TestCase):
    """Test the RateTracker orchestrator."""

    def _make_config(self, **overrides):
        """Build a rate limit config for testing."""
        config = {
            "tools": {
                "rm": {
                    "max_calls": 10,
                    "window_seconds": 60,
                    "on_exceed": "deny",
                },
                "bash": {
                    "max_calls": 30,
                    "window_seconds": 60,
                    "on_exceed": "escalate",
                },
            },
            "tier_defaults": {
                "read_only": {
                    "max_calls": 120,
                    "window_seconds": 60,
                    "on_exceed": "deny",
                },
                "destructive": {
                    "max_calls": 30,
                    "window_seconds": 60,
                    "on_exceed": "escalate",
                },
            },
            "global": {
                "max_calls": 200,
                "window_seconds": 60,
                "on_exceed": "read_only",
            },
            "circuit_breaker": {
                "enabled": False,
            },
        }
        config.update(overrides)
        return config

    @patch("agent_gate.rate_tracker.time")
    def test_per_tool_limit(self, mock_time):
        """Tool-specific limit triggers when exceeded."""
        mock_time.monotonic.return_value = 0.0
        tracker = RateTracker(self._make_config())

        # Record 10 rm calls (at the limit).
        for _ in range(10):
            tracker.record_call("rm", "destructive")

        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "tool")
        self.assertEqual(result["on_exceed"], "deny")

    @patch("agent_gate.rate_tracker.time")
    def test_per_tier_default(self, mock_time):
        """
        Tier default applies when no tool-specific limit exists.

        The tool 'cat' is not in the tools config, but its tier
        (read_only) has a default limit.
        """
        mock_time.monotonic.return_value = 0.0
        tracker = RateTracker(self._make_config())

        # Record 120 read_only calls with an unlisted tool.
        for _ in range(120):
            tracker.record_call("cat", "read_only")

        result = tracker.check_rate_limit("cat", "read_only")
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "tier")

    @patch("agent_gate.rate_tracker.time")
    def test_global_limit(self, mock_time):
        """Global limit triggers when total calls exceed threshold."""
        mock_time.monotonic.return_value = 0.0
        # Config with high tool/tier limits but low global.
        config = self._make_config()
        config["global"]["max_calls"] = 15
        tracker = RateTracker(config)

        # Record calls with an unlisted tool in an unlisted tier,
        # so only the global counter increments.
        for _ in range(15):
            tracker.record_call("unknown_tool", "unknown_tier")

        result = tracker.check_rate_limit("unknown_tool", "unknown_tier")
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "global")
        self.assertEqual(result["on_exceed"], "read_only")

    @patch("agent_gate.rate_tracker.time")
    def test_priority_tool_before_tier(self, mock_time):
        """Tool limit is checked before tier default."""
        mock_time.monotonic.return_value = 0.0
        # rm has max_calls=10, destructive tier has max_calls=30.
        tracker = RateTracker(self._make_config())

        for _ in range(10):
            tracker.record_call("rm", "destructive")

        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "tool")

    @patch("agent_gate.rate_tracker.time")
    def test_priority_tier_before_global(self, mock_time):
        """Tier limit is checked before global."""
        mock_time.monotonic.return_value = 0.0
        config = self._make_config()
        config["tier_defaults"]["destructive"]["max_calls"] = 5
        config["global"]["max_calls"] = 200
        tracker = RateTracker(config)

        # Use an unlisted tool so it skips tool check,
        # but hits the tier default.
        for _ in range(5):
            tracker.record_call("chmod", "destructive")

        result = tracker.check_rate_limit("chmod", "destructive")
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "tier")

    def test_disabled_tracker(self):
        """Empty/None config makes all methods no-ops."""
        tracker = RateTracker(None)
        tracker.record_call("rm", "destructive")
        tracker.record_outcome("rm", success=True)
        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNone(result)
        self.assertEqual(tracker.get_rate_context(), {})
        self.assertEqual(tracker.breaker_state, BreakerState.CLOSED)

    def test_empty_config_is_disabled(self):
        """An empty dict config also disables the tracker."""
        tracker = RateTracker({})
        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNone(result)

    @patch("agent_gate.rate_tracker.time")
    def test_allowed_when_under_limit(self, mock_time):
        """Check returns None when all counters are under their limits."""
        mock_time.monotonic.return_value = 0.0
        tracker = RateTracker(self._make_config())

        tracker.record_call("rm", "destructive")
        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNone(result)

    @patch("agent_gate.rate_tracker.time")
    def test_circuit_breaker_integration(self, mock_time):
        """Circuit breaker denial takes highest priority."""
        mock_time.monotonic.return_value = 0.0
        config = self._make_config()
        config["circuit_breaker"] = {
            "enabled": True,
            "sliding_window_size": 10,
            "minimum_calls": 5,
            "failure_rate_threshold": 0.50,
            "wait_duration_open_seconds": 30,
            "permitted_calls_half_open": 3,
            "on_trip": "read_only",
            "message": "Breaker tripped.",
        }
        tracker = RateTracker(config)

        # Trip the breaker with failures.
        for _ in range(5):
            tracker.record_outcome("rm", success=False)

        # Destructive call should be denied by breaker.
        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "circuit_breaker")

        # Read-only call should still be allowed.
        result = tracker.check_rate_limit("cat", "read_only")
        self.assertIsNone(result)

    @patch("agent_gate.rate_tracker.time")
    def test_get_rate_context(self, mock_time):
        """Rate context dict has expected structure."""
        mock_time.monotonic.return_value = 0.0
        tracker = RateTracker(self._make_config())

        tracker.record_call("rm", "destructive")
        tracker.record_call("rm", "destructive")

        ctx = tracker.get_rate_context()
        self.assertIn("tool_counts", ctx)
        self.assertIn("tier_counts", ctx)
        self.assertIn("global_count", ctx)
        self.assertIn("circuit_breaker", ctx)

        self.assertAlmostEqual(
            ctx["tool_counts"]["rm"]["count"], 2.0, places=1
        )
        self.assertAlmostEqual(
            ctx["tier_counts"]["destructive"]["count"], 2.0, places=1
        )

    @patch("agent_gate.rate_tracker.time")
    def test_backoff_tracking(self, mock_time):
        """Consecutive violations increase retry_after_seconds."""
        mock_time.monotonic.return_value = 0.0
        config = self._make_config()
        config["backoff"] = {
            "enabled": True,
            "initial_wait_seconds": 5,
            "multiplier": 2.0,
            "max_wait_seconds": 300,
        }
        tracker = RateTracker(config)

        # Fill up rm counter to trigger violations.
        for _ in range(10):
            tracker.record_call("rm", "destructive")

        # First violation: 5s.
        result1 = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result1)
        self.assertAlmostEqual(
            result1["retry_after_seconds"], 5.0, places=1
        )

        # Second violation: 10s.
        result2 = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result2)
        self.assertAlmostEqual(
            result2["retry_after_seconds"], 10.0, places=1
        )

        # Third violation: 20s.
        result3 = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result3)
        self.assertAlmostEqual(
            result3["retry_after_seconds"], 20.0, places=1
        )

    @patch("agent_gate.rate_tracker.time")
    def test_backoff_reset_on_success(self, mock_time):
        """Successful outcome resets the backoff counter."""
        mock_time.monotonic.return_value = 0.0
        config = self._make_config()
        config["backoff"] = {
            "enabled": True,
            "initial_wait_seconds": 5,
            "multiplier": 2.0,
            "max_wait_seconds": 300,
        }
        tracker = RateTracker(config)

        # Fill up rm counter and trigger a violation.
        for _ in range(10):
            tracker.record_call("rm", "destructive")

        result1 = tracker.check_rate_limit("rm", "destructive")
        self.assertAlmostEqual(
            result1["retry_after_seconds"], 5.0, places=1
        )

        # Record a successful outcome to reset backoff.
        tracker.record_outcome("rm", success=True)

        # Next violation should restart at initial wait.
        result2 = tracker.check_rate_limit("rm", "destructive")
        self.assertAlmostEqual(
            result2["retry_after_seconds"], 5.0, places=1
        )

    @patch("agent_gate.rate_tracker.time")
    def test_backoff_max_cap(self, mock_time):
        """Backoff wait time is capped at max_wait_seconds."""
        mock_time.monotonic.return_value = 0.0
        config = self._make_config()
        config["backoff"] = {
            "enabled": True,
            "initial_wait_seconds": 100,
            "multiplier": 2.0,
            "max_wait_seconds": 300,
        }
        tracker = RateTracker(config)

        for _ in range(10):
            tracker.record_call("rm", "destructive")

        # First: 100, second: 200, third: 300 (capped).
        tracker.check_rate_limit("rm", "destructive")
        tracker.check_rate_limit("rm", "destructive")
        result = tracker.check_rate_limit("rm", "destructive")
        self.assertLessEqual(result["retry_after_seconds"], 300.0)

    @patch("agent_gate.rate_tracker.time")
    def test_no_backoff_when_disabled(self, mock_time):
        """No retry_after_seconds when backoff config is absent."""
        mock_time.monotonic.return_value = 0.0
        tracker = RateTracker(self._make_config())

        for _ in range(10):
            tracker.record_call("rm", "destructive")

        result = tracker.check_rate_limit("rm", "destructive")
        self.assertIsNotNone(result)
        self.assertNotIn("retry_after_seconds", result)

    @patch("agent_gate.rate_tracker.time")
    def test_breaker_state_property(self, mock_time):
        """breaker_state property reflects the circuit breaker state."""
        mock_time.monotonic.return_value = 0.0
        config = self._make_config()
        config["circuit_breaker"] = {
            "enabled": True,
            "sliding_window_size": 10,
            "minimum_calls": 5,
            "failure_rate_threshold": 0.50,
            "wait_duration_open_seconds": 10,
            "permitted_calls_half_open": 3,
            "on_trip": "read_only",
            "message": "Tripped.",
        }
        tracker = RateTracker(config)

        self.assertEqual(tracker.breaker_state, BreakerState.CLOSED)

        for _ in range(5):
            tracker.record_outcome("rm", success=False)

        self.assertEqual(tracker.breaker_state, BreakerState.OPEN)


if __name__ == "__main__":
    unittest.main()
