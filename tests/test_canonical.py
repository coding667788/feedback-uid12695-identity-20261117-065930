import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution.canonical import MAX_SAFE_INTEGER, canonicalize
from solution.errors import CanonicalError
from solution.parser import parse


def canon(data):
    return canonicalize(parse(data))


class TestCanonicalForm(unittest.TestCase):
    def test_keys_sorted_by_code_point_and_compact(self):
        self.assertEqual(
            canon(b'{"b":1,"a":2,"\xf0\x9f\x98\x80":3}'),
            '{"a":2,"b":1,"😀":3}'.encode("utf-8"))

    def test_array_order_preserved(self):
        self.assertEqual(canon(b'{"a":[3,1,2]}'), b'{"a":[3,1,2]}')

    def test_negative_zero_normalized(self):
        self.assertEqual(canon(b'{"amount":-0}'), b'{"amount":0}')

    def test_safe_range_boundaries_accepted(self):
        self.assertEqual(
            canon(b'{"v":9007199254740991}'), b'{"v":9007199254740991}')
        self.assertEqual(
            canon(b'{"v":-9007199254740991}'), b'{"v":-9007199254740991}')

    def test_non_ascii_emitted_as_raw_utf8(self):
        self.assertEqual(
            canon('{"role":"😀-admin"}'.encode("utf-8")),
            '{"role":"😀-admin"}'.encode("utf-8"))

    def test_control_character_escaped(self):
        self.assertEqual(canon(b'"\\u0001"'), b'"\\u0001"')

    def test_idempotent_on_valid_documents(self):
        for doc in (b'{"tenant":"acme","amount":100,"role":"user"}',
                    b'{"a":[{"b":1},[2,3],"x"],"z":-0}',
                    '{"emoji":"😀","s":"\\t\\n"}'.encode("utf-8")):
            once = canon(doc)
            twice = canonicalize(parse(once))
            self.assertEqual(once, twice)


class TestCanonicalRejection(unittest.TestCase):
    def assertCanonicalError(self, data, code, offset=None):
        with self.assertRaises(CanonicalError) as cm:
            canon(data)
        self.assertEqual(cm.exception.code, code)
        if offset is not None:
            self.assertEqual(cm.exception.offset, offset)

    def test_top_level_duplicate_rejected(self):
        self.assertCanonicalError(b'{"a":1,"a":2}', "E_DUP_KEY")

    def test_nested_duplicate_rejected(self):
        self.assertCanonicalError(b'{"a":{"x":1,"x":2}}', "E_DUP_KEY")

    def test_deeply_nested_duplicate_rejected(self):
        self.assertCanonicalError(b'[[[{"k":1,"k":2}]]]', "E_DUP_KEY")

    def test_escaped_duplicate_rejected_with_byte_offset(self):
        data = b'{"tenant":1,"ten\\u0061nt":2}'
        self.assertCanonicalError(data, "E_DUP_KEY", data.index(b'"ten\\'))

    def test_integer_above_2p53_minus_1_rejected(self):
        self.assertCanonicalError(b'{"v":9007199254740992}', "E_RANGE")
        self.assertCanonicalError(b'{"v":-9007199254740992}', "E_RANGE")

    def test_non_integer_numbers_rejected(self):
        self.assertCanonicalError(b'{"v":1.5}', "E_NON_INTEGER")
        self.assertCanonicalError(b'{"v":1e2}', "E_NON_INTEGER")
        self.assertCanonicalError(b'{"v":-0.0}', "E_NON_INTEGER")

    def test_max_safe_integer_constant(self):
        self.assertEqual(MAX_SAFE_INTEGER, 2**53 - 1)


if __name__ == "__main__":
    unittest.main()
