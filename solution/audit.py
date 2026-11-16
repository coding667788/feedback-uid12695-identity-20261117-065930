"""Per-case analysis pipeline: parse -> diff -> canonicalize -> sign/verify.

Verdicts:
    pass                          parsed, canonicalized, no dangerous diff
    risky                         parsed, at least one dangerous semantic diff
    rejected-by-canonicalization  parsed, no dangerous diff, but the safe
                                  canonical form refused the document
    rejected-unparseable          the bytes are not acceptable JSON
    error                         the case definition itself is broken
"""

import hashlib
from typing import List

from .canonical import canonicalize
from .diff import diff_paths
from .errors import CanonicalError, ParseError
from .parser import DEFAULT_MAX_DEPTH, parse
from .signature import read_verified, sign_tree, verify_tree

DEFAULT_PROTECTED_PATHS = ["tenant", "amount", "role"]


def analyze_bytes(data: bytes, *, name: str, source: dict,
                  protected_paths: List[str] = DEFAULT_PROTECTED_PATHS,
                  max_depth: int = DEFAULT_MAX_DEPTH) -> dict:
    result = {"name": name, "source": source}

    # 1. Parse raw bytes into the information-preserving tree.
    try:
        tree = parse(data, max_depth=max_depth)
    except ParseError as exc:
        result["parse"] = {"ok": False, "error": exc.to_dict()}
        result["authorization_risk"] = False
        result["verdict"] = "rejected-unparseable"
        return result
    result["parse"] = {"ok": True}

    # 2. Semantic diff of protected paths between gateway and service views.
    diffs = diff_paths(tree, protected_paths)
    result["diffs"] = [d.to_dict() for d in diffs]
    dangerous = [d for d in diffs if d.dangerous]
    result["authorization_risk"] = bool(dangerous)
    result["risk_reasons"] = [
        f"{d.path}: {d.classification} "
        f"(gateway={d.gateway.to_dict()['value']!r}, "
        f"service={d.service.to_dict()['value']!r})"
        for d in dangerous
    ]

    # 3. Safe canonical form; a document that fails here cannot be signed.
    try:
        canonical = canonicalize(tree)
    except CanonicalError as exc:
        result["canonical"] = {"ok": False, "error": exc.to_dict()}
        result["signature"] = None
        result["verified_read"] = None
        result["verdict"] = "risky" if dangerous else "rejected-by-canonicalization"
        return result
    result["canonical"] = {
        "ok": True,
        "utf8": canonical.decode("utf-8"),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }

    # 4. Sign and verify the SAME tree, then read protected fields from it.
    signature = sign_tree(tree)
    signature["verified"] = verify_tree(tree, signature["signature"])
    result["signature"] = signature
    result["verified_read"] = {
        path: evidence.to_dict()
        for path, evidence in read_verified(tree, protected_paths).items()
    }
    result["verdict"] = "risky" if dangerous else "pass"
    return result
