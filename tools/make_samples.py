"""Regenerate all sample inputs under samples/ deterministically.

Run from the project root:  python tools/make_samples.py
No randomness, no timestamps -- re-running produces byte-identical files.
"""

from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# name -> exact bytes written to samples/<name>
FILES = {
    # -- benign / pass ------------------------------------------------------
    "valid-basic.json":
        b'{"tenant":"acme","amount":100,"role":"user"}',
    "valid-safe-max.json":
        # 2^53-1 is the largest canonical-safe integer and is exact in IEEE754.
        b'{"tenant":"acme","amount":9007199254740991,"role":"user"}',
    "negative-zero.json":
        # -0 must canonicalize to 0; both number policies read it as 0.
        b'{"tenant":"acme","amount":-0,"role":"user"}',
    "surrogate-pair.json":
        # escaped surrogate pair in a protected value
        b'{"tenant":"acme","amount":7,"role":"\\uD83D\\uDE00-admin"}',
    "key-order.json":
        # harmless reordering: canonical form sorts keys, views stay equal
        b'{"role":"user","amount":5,"tenant":"acme"}',

    # -- duplicate keys -----------------------------------------------------
    "dup-role-escalation.json":
        # gateway (first-key) sees "user", service (last-key) sees "admin"
        b'{"tenant":"acme","amount":10,"role":"user","role":"admin"}',
    "dup-role-reordered.json":
        # same attack with the pair swapped: gateway sees "admin" first
        b'{"role":"admin","role":"user","tenant":"acme","amount":10}',
    "dup-tenant-nested.json":
        # duplicate key one level down; canonicalization must still reject
        b'{"tenant":"acme","amount":5,"role":"user",'
        b'"profile":{"tenant":"acme","tenant":"evil"}}',
    "escaped-duplicate-key.json":
        # "ten nt" collides with "tenant" only after escape decoding
        b'{"tenant":"acme","ten\\u0061nt":"evil","amount":1,"role":"user"}',
    "dup-tenant-type.json":
        # first occurrence is a string, second an object -> type confusion
        b'{"tenant":"acme","tenant":{"admin":true},"amount":1,"role":"user"}',

    # -- numbers near 2^53 ----------------------------------------------------
    "amount-2p53-plus1.json":
        # 2^53+1: exact under Decimal, rounds down to 2^53 under IEEE754
        b'{"tenant":"acme","amount":9007199254740993,"role":"user"}',
    "serialization-only-dup.json":
        # 1e2 and 100 are the same value: serialization differs, data does not
        b'{"tenant":"acme","amount":1e2,"amount":100,"role":"user"}',

    # -- malformed inputs -----------------------------------------------------
    "bad-utf8.bin":
        b'{"tenant":"acme","amount":1,"role":"us\xffer"}',
    "lone-surrogate.json":
        b'{"tenant":"acme","amount":1,"role":"\\uD800x"}',
    "deep-nesting.json":
        b"[" * 200 + b"]" * 200,
    "trailing-data.json":
        b'{"tenant":"acme","amount":1,"role":"user"} {"extra":true}',
}


def main():
    SAMPLES.mkdir(exist_ok=True)
    for name, data in sorted(FILES.items()):
        (SAMPLES / name).write_bytes(data)
        print(f"wrote samples/{name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
