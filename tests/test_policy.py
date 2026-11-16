import sys
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution.parser import parse
from solution.policy import (EXACT_INTEGER, FIRST_KEY, IEEE754, LAST_KEY,
                             extract_path, resolve)


class TestObjectPolicies(unittest.TestCase):
    def test_first_key_keeps_first_occurrence(self):
        tree = parse(b'{"a":1,"a":2}')
        self.assertEqual(resolve(tree, FIRST_KEY, EXACT_INTEGER),
                         {"a": Decimal(1)})

    def test_last_key_keeps_last_occurrence(self):
        tree = parse(b'{"a":1,"a":2}')
        self.assertEqual(resolve(tree, LAST_KEY, EXACT_INTEGER),
                         {"a": Decimal(2)})

    def test_nested_duplicate_resolved_per_policy(self):
        tree = parse(b'{"o":{"r":"x","r":"y"}}')
        self.assertEqual(resolve(tree, FIRST_KEY, EXACT_INTEGER)["o"]["r"], "x")
        self.assertEqual(resolve(tree, LAST_KEY, EXACT_INTEGER)["o"]["r"], "y")


class TestNumberPolicies(unittest.TestCase):
    def test_exact_integer_keeps_full_precision(self):
        tree = parse(b'{"amount":9007199254740993}')
        value = resolve(tree, FIRST_KEY, EXACT_INTEGER)["amount"]
        self.assertEqual(value, Decimal("9007199254740993"))

    def test_ieee754_rounds_above_2p53(self):
        tree = parse(b'{"amount":9007199254740993}')
        value = resolve(tree, FIRST_KEY, IEEE754)["amount"]
        self.assertEqual(value, 9007199254740992.0)  # 2^53, silently rounded

    def test_2p53_minus_1_exact_in_both_policies(self):
        tree = parse(b'{"amount":9007199254740991}')
        self.assertEqual(resolve(tree, FIRST_KEY, EXACT_INTEGER)["amount"],
                         Decimal("9007199254740991"))
        self.assertEqual(resolve(tree, FIRST_KEY, IEEE754)["amount"],
                         9007199254740991.0)

    def test_negative_zero_is_zero_under_both_policies(self):
        tree = parse(b'{"amount":-0}')
        self.assertEqual(resolve(tree, FIRST_KEY, EXACT_INTEGER)["amount"], 0)
        self.assertEqual(resolve(tree, FIRST_KEY, IEEE754)["amount"], 0.0)


class TestExtractPath(unittest.TestCase):
    def test_occurrence_count_and_raw_text_recorded(self):
        tree = parse(b'{"tenant":"a","tenant":"b"}')
        first = extract_path(tree, ["tenant"], FIRST_KEY, EXACT_INTEGER)
        last = extract_path(tree, ["tenant"], LAST_KEY, EXACT_INTEGER)
        self.assertEqual((first.value, first.occurrences), ("a", 2))
        self.assertEqual((last.value, last.occurrences), ("b", 2))

    def test_number_evidence_keeps_raw(self):
        tree = parse(b'{"amount":1e2}')
        ev = extract_path(tree, ["amount"], FIRST_KEY, EXACT_INTEGER)
        self.assertEqual((ev.kind, ev.raw, ev.value), ("number", "1e2", Decimal("1E+2")))

    def test_missing_path(self):
        tree = parse(b'{"tenant":"a"}')
        ev = extract_path(tree, ["role"], FIRST_KEY, EXACT_INTEGER)
        self.assertFalse(ev.present)
        self.assertEqual(ev.kind, "missing")

    def test_dotted_path_through_duplicate_objects(self):
        tree = parse(b'{"profile":{"role":"x"},"profile":{}}')
        first = extract_path(tree, ["profile", "role"], FIRST_KEY, EXACT_INTEGER)
        last = extract_path(tree, ["profile", "role"], LAST_KEY, EXACT_INTEGER)
        self.assertTrue(first.present)
        self.assertFalse(last.present)


if __name__ == "__main__":
    unittest.main()
