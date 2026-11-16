"""Interpretation policies: how a component turns the parse tree into values.

Two independent axes, matching the two places real gateways and services
diverge:

Object member selection (duplicate keys):
    FIRST_KEY  -- keep the first occurrence (typical of hand-rolled parsers)
    LAST_KEY   -- keep the last occurrence  (typical of dict-based parsers)

Number interpretation:
    EXACT_INTEGER -- exact decimal semantics via ``decimal.Decimal``; the
                     source text is never rounded (e.g. 9007199254740993
                     stays 9007199254740993).
    IEEE754       -- binary64 semantics via ``float``; 9007199254740993
                     silently rounds to 9007199254740992.0.

``resolve`` materializes a whole subtree under one policy pair.
``extract_path`` reads a single dotted path and returns a ``PathEvidence``
record that also keeps the raw number text and duplicate-key occurrence
count, so the diff stage can tell "same value, different serialization"
apart from "different value".
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, List, Optional

from .nodes import JArray, JLiteral, JNumber, JObject, JString

FIRST_KEY = "first-key"
LAST_KEY = "last-key"
EXACT_INTEGER = "exact-integer"
IEEE754 = "ieee754"

OBJECT_POLICIES = (FIRST_KEY, LAST_KEY)
NUMBER_POLICIES = (EXACT_INTEGER, IEEE754)


def resolve_number(raw: str, number_policy: str):
    """Interpret one raw number token under a number policy."""
    if number_policy == EXACT_INTEGER:
        return Decimal(raw)
    if number_policy == IEEE754:
        return float(raw)
    raise ValueError(f"unknown number policy: {number_policy!r}")


def resolve(node, object_policy=FIRST_KEY, number_policy=EXACT_INTEGER):
    """Materialize a subtree as plain Python values under the given policies."""
    if isinstance(node, JObject):
        out = {}
        for key, _offset, child in node.pairs:
            value = resolve(child, object_policy, number_policy)
            if object_policy == FIRST_KEY:
                if key not in out:
                    out[key] = value
            elif object_policy == LAST_KEY:
                out[key] = value
            else:
                raise ValueError(f"unknown object policy: {object_policy!r}")
        return out
    if isinstance(node, JArray):
        return [resolve(item, object_policy, number_policy) for item in node.items]
    if isinstance(node, JString):
        return node.value
    if isinstance(node, JNumber):
        return resolve_number(node.raw, number_policy)
    if isinstance(node, JLiteral):
        return node.value
    raise TypeError(f"unknown node: {node!r}")


@dataclass
class PathEvidence:
    """What one component sees at one protected path, plus provenance."""

    path: str
    present: bool
    kind: str = "missing"  # number|string|bool|null|object|array|missing
    value: Any = None
    raw: Optional[str] = None       # raw number text, when kind == "number"
    occurrences: int = 0            # duplicate-key count at the final segment
    offset: Optional[int] = None    # byte offset of the chosen value token

    def to_dict(self):
        return {
            "present": self.present,
            "kind": self.kind,
            "value": json_safe(self.value),
            "raw": self.raw,
            "occurrences": self.occurrences,
            "offset": self.offset,
        }


def _kind_of(node):
    if isinstance(node, JNumber):
        return "number"
    if isinstance(node, JString):
        return "string"
    if isinstance(node, JLiteral):
        return "null" if node.value is None else "bool"
    if isinstance(node, JObject):
        return "object"
    return "array"


def extract_path(node, segments: List[str], object_policy, number_policy) -> PathEvidence:
    """Read a dotted path from the tree under one policy pair.

    At each object level, members matching the segment are collected in
    source order; the policy picks the first or the last. ``occurrences``
    reports how many members matched at the *final* segment (>=2 means the
    value came from a duplicate key).
    """
    path = ".".join(segments)
    current = node
    chosen = None
    occurrences = 0
    for index, segment in enumerate(segments):
        if not isinstance(current, JObject):
            return PathEvidence(path=path, present=False)
        matches = [(off, child) for key, off, child in current.pairs if key == segment]
        if not matches:
            return PathEvidence(path=path, present=False)
        offset, chosen = matches[0] if object_policy == FIRST_KEY else matches[-1]
        if index == len(segments) - 1:
            occurrences = len(matches)
        current = chosen
    kind = _kind_of(chosen)
    if kind == "number":
        return PathEvidence(
            path=path, present=True, kind=kind,
            value=resolve_number(chosen.raw, number_policy),
            raw=chosen.raw, occurrences=occurrences, offset=chosen.offset,
        )
    return PathEvidence(
        path=path, present=True, kind=kind,
        value=resolve(chosen, object_policy, number_policy),
        raw=None, occurrences=occurrences, offset=chosen.offset,
    )


def json_safe(value):
    """Convert resolved values into JSON-serializable form without precision loss.

    Numbers are rendered as strings (``Decimal`` exactly, floats via repr-like
    ``str``), so the report never silently rounds a 2^53-scale amount.
    """
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    return value
