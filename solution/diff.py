"""Semantic diff of protected paths between two interpretation profiles.

The simulated boundary (fixed by the audit, see README):

    gateway profile: object=first-key, number=exact-integer
    service profile: object=last-key,  number=ieee754

Classifications per protected path:

    absent              -- missing under both profiles (not dangerous)
    equal               -- same value, same provenance
    serialization_only  -- same semantic value, but the serialization was
                           ambiguous (different raw number text, or the value
                           came from a duplicate key). NOT an authorization
                           difference by itself, still reported as evidence.
    value_diff          -- different values            -> authorization risk
    type_diff           -- different JSON kinds        -> authorization risk
    presence_diff       -- present on one side only    -> authorization risk
"""

from dataclasses import dataclass
from typing import List, Sequence

from .policy import (EXACT_INTEGER, FIRST_KEY, IEEE754, LAST_KEY, PathEvidence,
                     extract_path)

DANGEROUS_CLASSIFICATIONS = frozenset({"value_diff", "type_diff", "presence_diff"})

GATEWAY_PROFILE = {"object": FIRST_KEY, "number": EXACT_INTEGER}
SERVICE_PROFILE = {"object": LAST_KEY, "number": IEEE754}


@dataclass
class Diff:
    path: str
    classification: str
    dangerous: bool
    gateway: PathEvidence
    service: PathEvidence

    def to_dict(self):
        return {
            "path": self.path,
            "classification": self.classification,
            "dangerous": self.dangerous,
            "gateway": self.gateway.to_dict(),
            "service": self.service.to_dict(),
        }


def classify(gateway: PathEvidence, service: PathEvidence):
    """Return (classification, dangerous) for one path under both profiles."""
    if not gateway.present and not service.present:
        return "absent", False
    if gateway.present != service.present:
        return "presence_diff", True
    if gateway.kind != service.kind:
        return "type_diff", True
    if gateway.value == service.value:
        ambiguous = (
            gateway.raw != service.raw
            or gateway.occurrences > 1
            or service.occurrences > 1
        )
        return ("serialization_only", False) if ambiguous else ("equal", False)
    return "value_diff", True


def diff_paths(tree, paths: Sequence[str],
               gateway_profile=GATEWAY_PROFILE,
               service_profile=SERVICE_PROFILE) -> List[Diff]:
    """Compute the semantic diff for each protected path on one parse tree."""
    diffs = []
    for path in paths:
        segments = path.split(".")
        gateway = extract_path(tree, segments,
                               gateway_profile["object"], gateway_profile["number"])
        service = extract_path(tree, segments,
                               service_profile["object"], service_profile["number"])
        classification, dangerous = classify(gateway, service)
        diffs.append(Diff(path=path, classification=classification,
                          dangerous=dangerous, gateway=gateway, service=service))
    return diffs
