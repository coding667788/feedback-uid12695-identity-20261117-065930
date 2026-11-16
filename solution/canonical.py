"""Safe canonical representation.

Rules (fixed by the task, do not relax):

* Encoding: UTF-8, no insignificant whitespace.
* Object keys sorted by Unicode code point; array order preserved.
* Duplicate keys are rejected at *every* nesting level (E_DUP_KEY) -- keys
  are compared after escape decoding, so ``ten\\u0061nt`` collides with
  ``tenant``.
* Numbers must be integers in source syntax (no fraction, no exponent)
  with absolute value <= 2^53 - 1; anything else is rejected
  (E_NON_INTEGER / E_RANGE). Negative zero is emitted as ``0``.
* Strings are emitted with minimal escaping; non-ASCII characters are
  written as raw UTF-8 (never \\uXXXX), which keeps the form idempotent.

Because duplicates are rejected outright, a dangerous document cannot be
laundered into a valid signature by reordering its keys.
"""

import re

from .errors import CanonicalError
from .nodes import JArray, JLiteral, JNumber, JObject, JString

MAX_SAFE_INTEGER = 2**53 - 1  # 9007199254740991

_INTEGER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def encode_string(value: str) -> str:
    """Minimal JSON string encoding (raw UTF-8 for non-ASCII)."""
    parts = ['"']
    for ch in value:
        escaped = _SHORT_ESCAPES.get(ch)
        if escaped is not None:
            parts.append(escaped)
        elif ord(ch) < 0x20:
            parts.append("\\u%04x" % ord(ch))
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def canonicalize(node) -> bytes:
    """Validate the tree and return its canonical form as UTF-8 bytes."""
    return _emit(node).encode("utf-8")


def _emit(node) -> str:
    if isinstance(node, JObject):
        seen = set()
        for key, key_offset, _child in node.pairs:
            if key in seen:
                raise CanonicalError(
                    "E_DUP_KEY", f"duplicate object key {key!r}", key_offset)
            seen.add(key)
        ordered = sorted(node.pairs, key=lambda pair: pair[0])  # code-point order
        return "{" + ",".join(
            encode_string(key) + ":" + _emit(child)
            for key, _offset, child in ordered
        ) + "}"
    if isinstance(node, JArray):
        return "[" + ",".join(_emit(item) for item in node.items) + "]"
    if isinstance(node, JString):
        return encode_string(node.value)
    if isinstance(node, JNumber):
        raw = node.raw
        if _INTEGER_RE.match(raw) is None:
            raise CanonicalError(
                "E_NON_INTEGER",
                f"non-integer number {raw!r} not allowed in canonical form",
                node.offset)
        value = int(raw)
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError(
                "E_RANGE",
                f"integer {raw!r} exceeds safe range |v| <= 2^53-1",
                node.offset)
        return "0" if value == 0 else str(value)  # -0 normalizes to 0
    if isinstance(node, JLiteral):
        if node.value is None:
            return "null"
        return "true" if node.value else "false"
    raise TypeError(f"unknown node: {node!r}")
