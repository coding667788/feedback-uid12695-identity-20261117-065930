import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution.canonical import canonicalize
from solution.errors import CanonicalError
from solution.parser import parse
from solution.policy import resolve
from solution.signature import (ALGORITHM, read_verified, sign_tree,
                                verify_tree)

PATHS = ["tenant", "amount", "role"]


class TestSignatureFlow(unittest.TestCase):
    def test_sign_is_deterministic_with_fixed_seed(self):
        tree = parse(b'{"tenant":"acme","amount":100,"role":"user"}')
        first = sign_tree(tree)
        second = sign_tree(parse(b'{"tenant":"acme","amount":100,"role":"user"}'))
        self.assertEqual(first, second)
        self.assertEqual(first["algorithm"], ALGORITHM)
        self.assertEqual(len(first["signature"]), 64)

    def test_verify_accepts_same_tree_rejects_tampered(self):
        tree = parse(b'{"tenant":"acme","amount":100,"role":"user"}')
        signature = sign_tree(tree)["signature"]
        self.assertTrue(verify_tree(tree, signature))
        tampered = parse(b'{"tenant":"evil","amount":100,"role":"user"}')
        self.assertFalse(verify_tree(tampered, signature))

    def test_key_reorder_of_valid_doc_keeps_signature(self):
        # Benign reordering produces the same canonical bytes, hence the
        # same signature -- this is intended, not an escape.
        sig_a = sign_tree(parse(b'{"tenant":"acme","amount":1,"role":"user"}'))
        sig_b = sign_tree(parse(b'{"role":"user","amount":1,"tenant":"acme"}'))
        self.assertEqual(sig_a["signature"], sig_b["signature"])

    def test_dangerous_doc_cannot_escape_by_reordering_keys(self):
        # Every ordering of a duplicate-key document must fail
        # canonicalization, so no ordering can ever be signed.
        orderings = [
            b'{"role":"user","role":"admin","tenant":"acme","amount":10}',
            b'{"role":"admin","role":"user","tenant":"acme","amount":10}',
            b'{"tenant":"acme","role":"user","role":"admin","amount":10}',
            b'{"amount":10,"tenant":"acme","role":"admin","role":"user"}',
        ]
        for raw in orderings:
            with self.assertRaises(CanonicalError) as cm:
                sign_tree(parse(raw))
            self.assertEqual(cm.exception.code, "E_DUP_KEY")

    def test_escaped_duplicate_cannot_be_signed_either(self):
        raw = b'{"tenant":"acme","ten\\u0061nt":"evil","amount":1,"role":"user"}'
        with self.assertRaises(CanonicalError) as cm:
            sign_tree(parse(raw))
        self.assertEqual(cm.exception.code, "E_DUP_KEY")

    def test_business_read_uses_same_verified_tree(self):
        # Sign, verify, then read protected fields -- all from ONE tree.
        tree = parse(b'{"tenant":"acme","amount":100,"role":"user"}')
        signature = sign_tree(tree)["signature"]
        self.assertTrue(verify_tree(tree, signature))
        read = read_verified(tree, PATHS)
        self.assertEqual(read["tenant"].value, "acme")
        self.assertEqual(str(read["amount"].value), "100")
        self.assertEqual(read["role"].value, "user")
        # The read values must match what the canonical bytes actually say.
        canonical_tree = parse(canonicalize(tree))
        self.assertEqual(resolve(canonical_tree)["tenant"], read["tenant"].value)
        self.assertEqual(str(resolve(canonical_tree)["amount"]),
                         str(read["amount"].value))


if __name__ == "__main__":
    unittest.main()
