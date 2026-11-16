"""Signature simulation over the canonical form (stdlib hmac only).

The signing key is derived from a fixed seed so every run is reproducible
(固定种子可重放). This is a local simulation of the gateway/service boundary;
no real external service is involved.

Security invariant enforced by the API shape: ``sign_tree`` and
``verify_tree`` canonicalize the *same* parse tree that
``read_verified`` then reads protected fields from. Business logic must
never re-parse the raw bytes after verification -- it reads the already
validated tree.
"""

import hashlib
import hmac
from typing import Dict, List

from .canonical import canonicalize
from .policy import EXACT_INTEGER, FIRST_KEY, PathEvidence, extract_path

SEED = b"uid12695-json-sig-boundary-audit-fixed-seed-v1"
ALGORITHM = "HMAC-SHA256"

_KEY = hashlib.sha256(SEED).digest()


def sign_tree(tree) -> Dict[str, str]:
    """Canonicalize ``tree`` and sign it. Raises CanonicalError if invalid."""
    canonical = canonicalize(tree)
    return {
        "algorithm": ALGORITHM,
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "signature": hmac.new(_KEY, canonical, hashlib.sha256).hexdigest(),
    }


def verify_tree(tree, signature: str) -> bool:
    """Re-canonicalize the same tree and compare signatures in constant time."""
    canonical = canonicalize(tree)
    expected = hmac.new(_KEY, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def read_verified(tree, paths: List[str],
                  object_policy=FIRST_KEY,
                  number_policy=EXACT_INTEGER) -> Dict[str, PathEvidence]:
    """Business read of protected paths from the *same* verified tree.

    With a validated tree there are no duplicate keys and all numbers are
    safe integers, so first-key/last-key and exact/ieee754 coincide; the
    defaults simply mirror the gateway profile.
    """
    return {
        path: extract_path(tree, path.split("."), object_policy, number_policy)
        for path in paths
    }
