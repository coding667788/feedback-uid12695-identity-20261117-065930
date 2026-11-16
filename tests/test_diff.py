import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution.diff import diff_paths
from solution.parser import parse

PATHS = ["tenant", "amount", "role"]


def diff_by_path(data, paths=PATHS):
    return {d.path: d for d in diff_paths(parse(data), paths)}


class TestSemanticDiff(unittest.TestCase):
    def test_duplicate_role_escalation_is_value_diff(self):
        diffs = diff_by_path(
            b'{"tenant":"acme","amount":10,"role":"user","role":"admin"}')
        role = diffs["role"]
        self.assertEqual(role.classification, "value_diff")
        self.assertTrue(role.dangerous)
        self.assertEqual(role.gateway.value, "user")
        self.assertEqual(role.service.value, "admin")
        self.assertEqual(diffs["tenant"].classification, "equal")

    def test_amount_above_2p53_is_value_diff(self):
        diffs = diff_by_path(
            b'{"tenant":"acme","amount":9007199254740993,"role":"user"}')
        amount = diffs["amount"]
        self.assertEqual(amount.classification, "value_diff")
        self.assertTrue(amount.dangerous)
        self.assertEqual(amount.gateway.raw, "9007199254740993")
        self.assertEqual(str(amount.gateway.value), "9007199254740993")
        self.assertEqual(str(amount.service.value), "9007199254740992.0")

    def test_same_value_different_serialization_is_not_dangerous(self):
        # 1e2 vs 100: the two policies pick different duplicates, but the
        # semantic value is identical -> serialization_only, not dangerous.
        diffs = diff_by_path(
            b'{"tenant":"acme","amount":1e2,"amount":100,"role":"user"}')
        amount = diffs["amount"]
        self.assertEqual(amount.classification, "serialization_only")
        self.assertFalse(amount.dangerous)
        self.assertEqual(amount.gateway.raw, "1e2")
        self.assertEqual(amount.service.raw, "100")

    def test_identical_duplicate_value_is_serialization_only(self):
        diffs = diff_by_path(
            b'{"tenant":"acme","tenant":"acme","amount":1,"role":"user"}')
        tenant = diffs["tenant"]
        self.assertEqual(tenant.classification, "serialization_only")
        self.assertFalse(tenant.dangerous)

    def test_type_confusion_is_type_diff(self):
        diffs = diff_by_path(
            b'{"tenant":"acme","tenant":{"admin":true},"amount":1,"role":"user"}')
        tenant = diffs["tenant"]
        self.assertEqual(tenant.classification, "type_diff")
        self.assertTrue(tenant.dangerous)

    def test_presence_diff_on_nested_path(self):
        diffs = diff_by_path(
            b'{"profile":{"role":"x"},"profile":{}}', paths=["profile.role"])
        diff = diffs["profile.role"]
        self.assertEqual(diff.classification, "presence_diff")
        self.assertTrue(diff.dangerous)

    def test_clean_document_all_equal(self):
        diffs = diff_by_path(
            b'{"tenant":"acme","amount":100,"role":"user"}')
        self.assertEqual(
            {p: d.classification for p, d in diffs.items()},
            {"tenant": "equal", "amount": "equal", "role": "equal"})
        self.assertFalse(any(d.dangerous for d in diffs.values()))

    def test_missing_protected_path_is_absent_not_dangerous(self):
        diffs = diff_by_path(b'{"tenant":"acme"}')
        self.assertEqual(diffs["role"].classification, "absent")
        self.assertFalse(diffs["role"].dangerous)


if __name__ == "__main__":
    unittest.main()
