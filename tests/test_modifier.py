"""
Tests for Agent Gate modifier operations module.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_gate.modifier import (
    ModificationError,
    apply_modifications,
    clamp_permission,
    strip_flags,
    require_flags,
    append_arg,
    max_depth,
    OPERATION_HANDLERS,
)


class TestClampPermission(unittest.TestCase):
    """Tests for the clamp_permission operation."""

    def test_clamp_permission_reduces_777_to_755(self):
        result = clamp_permission("chmod", ["777", "deploy.sh"], "755")
        self.assertEqual(result, ["755", "deploy.sh"])

    def test_clamp_permission_no_op_when_below(self):
        result = clamp_permission("chmod", ["644", "file.txt"], "755")
        self.assertEqual(result, ["644", "file.txt"])

    def test_clamp_permission_no_op_when_equal(self):
        result = clamp_permission("chmod", ["755", "file.txt"], "755")
        self.assertEqual(result, ["755", "file.txt"])

    def test_clamp_permission_four_digit_octal(self):
        result = clamp_permission("chmod", ["0777", "file.txt"], "0755")
        self.assertEqual(result, ["0755", "file.txt"])

    def test_clamp_permission_invalid_max_perm(self):
        with self.assertRaises(ModificationError):
            clamp_permission("chmod", ["777", "file.txt"], "999")

    def test_clamp_permission_non_octal_arg_untouched(self):
        result = clamp_permission("chmod", ["+x", "file.txt"], "755")
        self.assertEqual(result, ["+x", "file.txt"])


class TestStripFlags(unittest.TestCase):
    """Tests for the strip_flags operation."""

    def test_strip_flags_removes_exact_match(self):
        result = strip_flags("rm", ["-f", "file.txt"], ["-f"])
        self.assertEqual(result, ["file.txt"])

    def test_strip_flags_combined_short_flags(self):
        result = strip_flags("rm", ["-rf", "dir/"], ["-f"])
        self.assertEqual(result, ["-r", "dir/"])

    def test_strip_flags_no_op_when_absent(self):
        result = strip_flags("rm", ["-r", "dir/"], ["-f"])
        self.assertEqual(result, ["-r", "dir/"])

    def test_strip_flags_multiple_flags(self):
        result = strip_flags(
            "rm", ["-rf", "--force", "dir/"], ["-f", "--force"]
        )
        self.assertEqual(result, ["-r", "dir/"])

    def test_strip_flags_idempotent(self):
        result = strip_flags("rm", ["-r", "dir/"], ["-f"])
        result2 = strip_flags("rm", result, ["-f"])
        self.assertEqual(result, ["-r", "dir/"])
        self.assertEqual(result2, ["-r", "dir/"])

    def test_strip_flags_invalid_type(self):
        with self.assertRaises(ModificationError):
            strip_flags("rm", ["-f", "file.txt"], "-f")


class TestRequireFlags(unittest.TestCase):
    """Tests for the require_flags operation."""

    def test_require_flags_injects_missing(self):
        result = require_flags(
            "curl", ["http://example.com"], ["--max-time 30"]
        )
        self.assertEqual(
            result, ["--max-time", "30", "http://example.com"]
        )

    def test_require_flags_no_op_when_present(self):
        result = require_flags(
            "curl",
            ["--max-time", "30", "http://example.com"],
            ["--max-time 30"],
        )
        self.assertEqual(
            result, ["--max-time", "30", "http://example.com"]
        )

    def test_require_flags_idempotent(self):
        result = require_flags(
            "curl", ["http://example.com"], ["--max-time 30"]
        )
        result2 = require_flags("curl", result, ["--max-time 30"])
        self.assertEqual(result, result2)

    def test_require_flags_invalid_type(self):
        with self.assertRaises(ModificationError):
            require_flags("curl", ["http://example.com"], "--max-time 30")


class TestAppendArg(unittest.TestCase):
    """Tests for the append_arg operation."""

    def test_append_arg_adds_when_absent(self):
        result = append_arg(
            "database_query",
            ["SELECT", "*", "FROM", "users"],
            "LIMIT 100",
        )
        self.assertEqual(
            result,
            ["SELECT", "*", "FROM", "users", "LIMIT", "100"],
        )

    def test_append_arg_no_op_when_present(self):
        result = append_arg(
            "database_query",
            ["SELECT", "*", "FROM", "users", "LIMIT", "100"],
            "LIMIT 100",
        )
        self.assertEqual(
            result,
            ["SELECT", "*", "FROM", "users", "LIMIT", "100"],
        )

    def test_append_arg_invalid_type(self):
        with self.assertRaises(ModificationError):
            append_arg("database_query", ["SELECT"], 100)


class TestMaxDepth(unittest.TestCase):
    """Tests for the max_depth operation."""

    def test_max_depth_clamps_existing(self):
        result = max_depth(
            "find", [".", "-maxdepth", "10", "-name", "*.py"], 2
        )
        self.assertEqual(
            result, [".", "-maxdepth", "2", "-name", "*.py"]
        )

    def test_max_depth_no_op_when_below(self):
        result = max_depth(
            "find", [".", "-maxdepth", "1", "-name", "*.py"], 2
        )
        self.assertEqual(
            result, [".", "-maxdepth", "1", "-name", "*.py"]
        )

    def test_max_depth_injects_when_absent(self):
        result = max_depth("find", [".", "-name", "*.py"], 2)
        self.assertEqual(
            result, [".", "-maxdepth", "2", "-name", "*.py"]
        )

    def test_max_depth_invalid_depth(self):
        with self.assertRaises(ModificationError):
            max_depth("find", [".", "-name", "*.py"], -1)

    def test_max_depth_non_find_command(self):
        result = max_depth("tree", ["./src"], 2)
        self.assertEqual(result, ["--max-depth=2", "./src"])


class TestApplyModifications(unittest.TestCase):
    """Tests for the apply_modifications dispatcher."""

    def test_apply_modifications_single_op(self):
        modified, ops = apply_modifications(
            "chmod", ["777", "deploy.sh"], {"clamp_permission": "755"}
        )
        self.assertEqual(modified, ["755", "deploy.sh"])
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["operation"], "clamp_permission")
        self.assertEqual(ops[0]["params"], "755")
        self.assertTrue(ops[0]["changed"])

    def test_apply_modifications_multiple_ops_yaml_order(self):
        modified, ops = apply_modifications(
            "rm",
            ["-rf", "dir/"],
            {"strip_flags": ["-f"], "require_flags": ["--interactive"]},
        )
        # First strips -f from -rf -> -r
        # Then injects --interactive
        self.assertEqual(
            modified, ["--interactive", "-r", "dir/"]
        )
        self.assertEqual(len(ops), 2)
        self.assertEqual(ops[0]["operation"], "strip_flags")
        self.assertTrue(ops[0]["changed"])
        self.assertEqual(ops[1]["operation"], "require_flags")
        self.assertTrue(ops[1]["changed"])

    def test_apply_modifications_unknown_op(self):
        with self.assertRaises(ModificationError) as ctx:
            apply_modifications("rm", ["-f"], {"unknown_op": "value"})
        self.assertIn("Unknown modify operation", str(ctx.exception))

    def test_apply_modifications_empty_block(self):
        modified, ops = apply_modifications(
            "rm", ["-f", "file.txt"], {}
        )
        self.assertEqual(modified, ["-f", "file.txt"])
        self.assertEqual(ops, [])

    def test_apply_modifications_no_change_tracked(self):
        """When an operation is a no-op, changed should be False."""
        modified, ops = apply_modifications(
            "chmod", ["644", "file.txt"], {"clamp_permission": "755"}
        )
        self.assertEqual(modified, ["644", "file.txt"])
        self.assertEqual(len(ops), 1)
        self.assertFalse(ops[0]["changed"])

    def test_apply_modifications_does_not_mutate_input(self):
        """Verify apply_modifications does not mutate the input args."""
        original = ["777", "deploy.sh"]
        original_copy = list(original)
        apply_modifications(
            "chmod", original, {"clamp_permission": "755"}
        )
        self.assertEqual(original, original_copy)


class TestOperationRegistry(unittest.TestCase):
    """Tests for the operation handler registry."""

    def test_all_five_operations_registered(self):
        expected = {
            "clamp_permission",
            "strip_flags",
            "require_flags",
            "append_arg",
            "max_depth",
        }
        self.assertEqual(set(OPERATION_HANDLERS.keys()), expected)


if __name__ == "__main__":
    unittest.main()
