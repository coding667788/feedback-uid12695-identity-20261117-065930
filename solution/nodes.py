"""Parse-tree node types.

The tree deliberately preserves information that a plain ``dict``-based parse
would destroy:

* ``JObject.pairs`` keeps *all* key/value members in original order, so
  duplicate keys survive.
* ``JNumber.raw`` keeps the exact source text of every number, so ``1e2``,
  ``100`` and ``9007199254740993`` are distinguishable before any numeric
  policy is applied.

Every node records the byte ``offset`` of the first byte of its token so that
later stages (canonicalization, reporting) can point back into the raw input.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class JObject:
    # pairs: list of (decoded_key, key_byte_offset, value_node) in source order.
    pairs: List[Tuple[str, int, "JNode"]]
    offset: int


@dataclass
class JArray:
    items: List["JNode"]
    offset: int


@dataclass
class JString:
    value: str
    offset: int


@dataclass
class JNumber:
    raw: str  # exact source text, ASCII per JSON number grammar
    offset: int


@dataclass
class JLiteral:
    value: Optional[bool]  # True, False or None (null)
    offset: int


JNode = object  # union of the five node types above
