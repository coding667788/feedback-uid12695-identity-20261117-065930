"""Byte-level JSON parser producing an information-preserving parse tree.

Design notes
------------
* The parser works directly on ``bytes`` (never pre-decodes the whole input),
  so every reported error offset is a **byte offset** and stays correct when
  the input is delivered as a stream of UTF-8 chunks.
* Duplicate object keys are preserved (``JObject.pairs`` is an ordered list).
* Numbers keep their exact source text (``JNumber.raw``); no float conversion
  happens at parse time.
* Strings support the full JSON escape set including ``\\uXXXX`` surrogate
  pairs; lone surrogates and invalid UTF-8 are rejected.
* Nesting deeper than ``max_depth`` (default 128) is rejected with E_DEPTH.

Error codes: E_UTF8, E_SYNTAX, E_UNICODE, E_DEPTH.
"""

import re

from .errors import ParseError
from .nodes import JArray, JLiteral, JNumber, JObject, JString

DEFAULT_MAX_DEPTH = 128

_NUMBER_RE = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEXDIGITS = frozenset(b"0123456789abcdefABCDEF")
_WS = (0x20, 0x09, 0x0A, 0x0D)  # space, tab, LF, CR

_SIMPLE_ESCAPES = {
    0x22: '"',   # \"
    0x5C: "\\",  # \\
    0x2F: "/",   # \/
    0x62: "\b",  # \b
    0x66: "\f",  # \f
    0x6E: "\n",  # \n
    0x72: "\r",  # \r
    0x74: "\t",  # \t
}


def parse(data, max_depth=DEFAULT_MAX_DEPTH):
    """Parse ``bytes`` into a parse tree. Raises ParseError on invalid input."""
    return _Parser(data, max_depth).parse()


class _Parser:
    def __init__(self, data, max_depth):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("parser input must be bytes")
        self.data = bytes(data)
        self.n = len(self.data)
        self.pos = 0
        self.max_depth = max_depth

    def fail(self, code, message, offset=None):
        raise ParseError(code, message, self.pos if offset is None else offset)

    # -- top level ---------------------------------------------------------

    def parse(self):
        self._skip_ws()
        node = self._value(1)
        self._skip_ws()
        if self.pos != self.n:
            self.fail("E_SYNTAX", "unexpected trailing data after top-level value")
        return node

    def _skip_ws(self):
        d, n, p = self.data, self.n, self.pos
        while p < n and d[p] in _WS:
            p += 1
        self.pos = p

    # -- values ------------------------------------------------------------

    def _value(self, depth):
        if depth > self.max_depth:
            self.fail("E_DEPTH", f"nesting deeper than max_depth={self.max_depth}")
        if self.pos >= self.n:
            self.fail("E_SYNTAX", "unexpected end of input, value expected")
        b = self.data[self.pos]
        if b == 0x7B:  # {
            return self._object(depth)
        if b == 0x5B:  # [
            return self._array(depth)
        if b == 0x22:  # "
            value, offset = self._string()
            return JString(value, offset)
        if b == 0x74:  # t
            return self._literal(b"true", True)
        if b == 0x66:  # f
            return self._literal(b"false", False)
        if b == 0x6E:  # n
            return self._literal(b"null", None)
        if b == 0x2D or 0x30 <= b <= 0x39:  # - or digit
            return self._number()
        self.fail("E_SYNTAX", f"unexpected byte 0x{b:02x}, value expected")

    def _literal(self, word, value):
        offset = self.pos
        if self.data[self.pos:self.pos + len(word)] != word:
            self.fail("E_SYNTAX", f"invalid literal, expected {word.decode()}", offset)
        self.pos += len(word)
        return JLiteral(value, offset)

    def _number(self):
        offset = self.pos
        m = _NUMBER_RE.match(self.data, self.pos)
        if m is None:
            self.fail("E_SYNTAX", "invalid number", offset)
        self.pos = m.end()
        return JNumber(m.group(0).decode("ascii"), offset)

    # -- strings -----------------------------------------------------------

    def _string(self):
        start = self.pos
        self.pos += 1  # opening quote
        out = []
        d = self.data
        while True:
            if self.pos >= self.n:
                self.fail("E_SYNTAX", "unterminated string", start)
            b = d[self.pos]
            if b == 0x22:  # closing quote
                self.pos += 1
                return "".join(out), start
            if b == 0x5C:  # backslash
                out.append(self._escape())
            elif b < 0x20:
                self.fail("E_SYNTAX", "unescaped control character in string")
            elif b < 0x80:
                out.append(chr(b))
                self.pos += 1
            else:
                out.append(self._utf8_char())

    def _escape(self):
        esc_offset = self.pos
        self.pos += 1  # backslash
        if self.pos >= self.n:
            self.fail("E_SYNTAX", "unterminated escape sequence", esc_offset)
        e = self.data[self.pos]
        self.pos += 1
        simple = _SIMPLE_ESCAPES.get(e)
        if simple is not None:
            return simple
        if e == 0x75:  # \u
            return self._unicode_escape(esc_offset)
        self.fail("E_SYNTAX", f"invalid escape \\{chr(e)}", esc_offset)

    def _hex4(self, offset):
        chunk = self.data[self.pos:self.pos + 4]
        if len(chunk) < 4 or any(c not in _HEXDIGITS for c in chunk):
            self.fail("E_UNICODE", "invalid \\uXXXX escape (need 4 hex digits)", offset)
        self.pos += 4
        return int(chunk.decode("ascii"), 16)

    def _unicode_escape(self, esc_offset):
        code = self._hex4(esc_offset)
        if 0xD800 <= code <= 0xDBFF:  # high surrogate: must pair with a low one
            pair_offset = self.pos
            if self.data[self.pos:self.pos + 2] == b"\\u":
                self.pos += 2
                low = self._hex4(pair_offset)
                if 0xDC00 <= low <= 0xDFFF:
                    combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    return chr(combined)
                self.fail("E_UNICODE",
                          "high surrogate not followed by low surrogate", pair_offset)
            self.fail("E_UNICODE", "lone high surrogate", esc_offset)
        if 0xDC00 <= code <= 0xDFFF:
            self.fail("E_UNICODE", "lone low surrogate", esc_offset)
        return chr(code)

    def _utf8_char(self):
        offset = self.pos
        b = self.data[self.pos]
        if 0xC2 <= b <= 0xDF:
            length = 2
        elif 0xE0 <= b <= 0xEF:
            length = 3
        elif 0xF0 <= b <= 0xF4:
            length = 4
        else:
            self.fail("E_UTF8", f"invalid UTF-8 lead byte 0x{b:02x}", offset)
        chunk = self.data[self.pos:self.pos + length]
        if len(chunk) < length:
            self.fail("E_UTF8", "truncated UTF-8 sequence", offset)
        try:
            ch = chunk.decode("utf-8")  # strict: rejects overlong/surrogate/>U+10FFFF
        except UnicodeDecodeError:
            self.fail("E_UTF8", "invalid UTF-8 sequence", offset)
        self.pos += length
        return ch

    # -- containers ----------------------------------------------------------

    def _object(self, depth):
        offset = self.pos
        self.pos += 1  # {
        pairs = []
        self._skip_ws()
        if self.pos < self.n and self.data[self.pos] == 0x7D:  # }
            self.pos += 1
            return JObject(pairs, offset)
        while True:
            self._skip_ws()
            if self.pos >= self.n or self.data[self.pos] != 0x22:
                self.fail("E_SYNTAX", "object key must be a string")
            key, key_offset = self._string()
            self._skip_ws()
            if self.pos >= self.n or self.data[self.pos] != 0x3A:  # :
                self.fail("E_SYNTAX", "expected ':' after object key")
            self.pos += 1
            self._skip_ws()
            value = self._value(depth + 1)
            pairs.append((key, key_offset, value))
            self._skip_ws()
            if self.pos >= self.n:
                self.fail("E_SYNTAX", "unterminated object", offset)
            b = self.data[self.pos]
            if b == 0x2C:  # ,
                self.pos += 1
                continue
            if b == 0x7D:  # }
                self.pos += 1
                return JObject(pairs, offset)
            self.fail("E_SYNTAX", "expected ',' or '}' in object")

    def _array(self, depth):
        offset = self.pos
        self.pos += 1  # [
        items = []
        self._skip_ws()
        if self.pos < self.n and self.data[self.pos] == 0x5D:  # ]
            self.pos += 1
            return JArray(items, offset)
        while True:
            self._skip_ws()
            items.append(self._value(depth + 1))
            self._skip_ws()
            if self.pos >= self.n:
                self.fail("E_SYNTAX", "unterminated array", offset)
            b = self.data[self.pos]
            if b == 0x2C:  # ,
                self.pos += 1
                continue
            if b == 0x5D:  # ]
                self.pos += 1
                return JArray(items, offset)
            self.fail("E_SYNTAX", "expected ',' or ']' in array")
