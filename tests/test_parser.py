import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution.errors import ParseError
from solution.nodes import JArray, JLiteral, JNumber, JObject, JString
from solution.parser import DEFAULT_MAX_DEPTH, parse


class TestParseTree(unittest.TestCase):
    def test_duplicate_keys_preserved_in_order(self):
        tree = parse(b'{"a":1,"a":2}')
        self.assertIsInstance(tree, JObject)
        self.assertEqual([k for k, _, _ in tree.pairs], ["a", "a"])
        self.assertEqual([v.raw for _, _, v in tree.pairs], ["1", "2"])

    def test_raw_number_text_preserved(self):
        tree = parse(b'{"x":1e2,"y":9007199254740993,"z":-0}')
        raws = {k: v.raw for k, _, v in tree.pairs}
        self.assertEqual(
            raws, {"x": "1e2", "y": "9007199254740993", "z": "-0"})

    def test_escaped_key_decodes_to_same_name(self):
        tree = parse(b'{"ten\\u0061nt":1,"tenant":2}')
        self.assertEqual([k for k, _, _ in tree.pairs], ["tenant", "tenant"])

    def test_surrogate_pair_escape(self):
        tree = parse(b'"\\uD83D\\uDE00"')
        self.assertEqual(tree.value, "\U0001F600")

    def test_literal_utf8_multibyte(self):
        tree = parse('{"k":"é😀"}'.encode("utf-8"))
        self.assertEqual(tree.pairs[0][2].value, "é😀")

    def test_node_offsets_are_byte_offsets(self):
        tree = parse(b'  {"ab":12}')
        self.assertEqual(tree.offset, 2)
        key, key_off, value = tree.pairs[0]
        self.assertEqual((key, key_off), ("ab", 3))
        self.assertEqual(value.offset, 8)


class TestParseRejection(unittest.TestCase):
    def assertParseError(self, data, code, offset=None):
        with self.assertRaises(ParseError) as cm:
            parse(data)
        self.assertEqual(cm.exception.code, code)
        if offset is not None:
            self.assertEqual(cm.exception.offset, offset)

    def test_lone_high_surrogate_rejected(self):
        self.assertParseError(b'"\\uD800x"', "E_UNICODE", 1)

    def test_lone_low_surrogate_rejected(self):
        self.assertParseError(b'"\\uDC00"', "E_UNICODE", 1)

    def test_high_surrogate_without_low_rejected(self):
        self.assertParseError(b'"\\uD83D\\u0041"', "E_UNICODE")

    def test_invalid_utf8_reports_byte_offset(self):
        data = b'{"a":"\xff"}'
        self.assertParseError(data, "E_UTF8", data.index(b"\xff"))

    def test_overlong_utf8_rejected(self):
        self.assertParseError(b'"\xc0\xaf"', "E_UTF8", 1)

    def test_error_offset_counts_bytes_not_chars(self):
        # "é" is 2 bytes; the '@' byte offset must reflect that.
        data = '{"a":"é","b":@}'.encode("utf-8")
        self.assertParseError(data, "E_SYNTAX", data.index(b"@"))

    def test_depth_limit_enforced(self):
        parse(b"[" * DEFAULT_MAX_DEPTH + b"]" * DEFAULT_MAX_DEPTH)  # ok
        deep = b"[" * (DEFAULT_MAX_DEPTH + 1) + b"]" * (DEFAULT_MAX_DEPTH + 1)
        self.assertParseError(deep, "E_DEPTH", DEFAULT_MAX_DEPTH)

    def test_trailing_data_rejected(self):
        self.assertParseError(b'{"a":1} 2', "E_SYNTAX", 8)

    def test_unescaped_control_character_rejected(self):
        self.assertParseError(b'"\x01"', "E_SYNTAX", 1)

    def test_leading_zero_rejected(self):
        self.assertParseError(b"01", "E_SYNTAX", 1)

    def test_invalid_escape_rejected(self):
        self.assertParseError(b'"\\q"', "E_SYNTAX", 1)

    def test_unterminated_string_rejected(self):
        self.assertParseError(b'"abc', "E_SYNTAX", 0)

    def test_literals(self):
        tree = parse(b"[true,false,null]")
        self.assertIsInstance(tree, JArray)
        self.assertEqual([i.value for i in tree.items], [True, False, None])
        self.assertTrue(all(isinstance(i, JLiteral) for i in tree.items))


if __name__ == "__main__":
    unittest.main()
