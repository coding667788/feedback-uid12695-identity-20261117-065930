import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution.__main__ import main

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CASES_JSON = PROJECT_ROOT / "cases.json"


def run_cli(output_path):
    rc = main(["--input", str(CASES_JSON), "--output", str(output_path)])
    return rc, json.loads(Path(output_path).read_text(encoding="utf-8"))


class TestCliCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.output = Path(cls._tmp.name) / "result.json"
        cls.rc, cls.report = run_cli(cls.output)
        cls.cases = {c["name"]: c for c in cls.report["cases"]}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def diff_of(self, case_name, path):
        case = self.cases[case_name]
        return next(d for d in case["diffs"] if d["path"] == path)

    def test_exit_code_and_summary(self):
        self.assertEqual(self.rc, 0)
        summary = self.report["summary"]
        self.assertEqual(summary["total"], 17)
        self.assertEqual(summary["pass"], 6)   # 5 valid files + inline-demo
        self.assertEqual(summary["risky"], 5)  # dup-role x2, escaped-dup,
                                               # dup-tenant-type, 2p53+1
        self.assertEqual(summary["rejected"], 6)
        self.assertEqual(summary["errors"], 0)

    def test_valid_basic_passes_with_exact_canonical_form(self):
        case = self.cases["valid-basic"]
        self.assertEqual(case["verdict"], "pass")
        self.assertFalse(case["authorization_risk"])
        self.assertEqual(case["canonical"]["utf8"],
                         '{"amount":100,"role":"user","tenant":"acme"}')
        self.assertTrue(case["signature"]["verified"])
        self.assertEqual(case["verified_read"]["tenant"]["value"], "acme")

    def test_negative_zero_canonicalizes_to_zero(self):
        case = self.cases["negative-zero"]
        self.assertEqual(case["verdict"], "pass")
        self.assertEqual(case["canonical"]["utf8"],
                         '{"amount":0,"role":"user","tenant":"acme"}')

    def test_surrogate_pair_value_round_trips(self):
        case = self.cases["surrogate-pair"]
        self.assertEqual(case["verdict"], "pass")
        self.assertEqual(case["canonical"]["utf8"],
                         '{"amount":7,"role":"😀-admin","tenant":"acme"}')
        self.assertEqual(case["verified_read"]["role"]["value"], "😀-admin")

    def test_safe_max_integer_passes(self):
        case = self.cases["valid-safe-max"]
        self.assertEqual(case["verdict"], "pass")
        self.assertEqual(self.diff_of("valid-safe-max", "amount")
                         ["classification"], "equal")

    def test_dup_role_escalation_flagged_and_unsigned(self):
        case = self.cases["dup-role-escalation"]
        self.assertEqual(case["verdict"], "risky")
        self.assertTrue(case["authorization_risk"])
        role = self.diff_of("dup-role-escalation", "role")
        self.assertEqual(role["classification"], "value_diff")
        self.assertEqual(role["gateway"]["value"], "user")
        self.assertEqual(role["service"]["value"], "admin")
        self.assertEqual(case["canonical"]["error"]["code"], "E_DUP_KEY")
        self.assertIsNone(case["signature"])

    def test_reordered_duplicate_also_flagged(self):
        case = self.cases["dup-role-reordered"]
        self.assertEqual(case["verdict"], "risky")
        role = self.diff_of("dup-role-reordered", "role")
        self.assertEqual(role["classification"], "value_diff")
        self.assertEqual(role["gateway"]["value"], "admin")
        self.assertEqual(role["service"]["value"], "user")
        self.assertEqual(case["canonical"]["error"]["code"], "E_DUP_KEY")

    def test_nested_duplicate_rejected_by_canonicalization(self):
        case = self.cases["dup-tenant-nested"]
        self.assertEqual(case["verdict"], "rejected-by-canonicalization")
        self.assertFalse(case["authorization_risk"])
        self.assertEqual(case["canonical"]["error"]["code"], "E_DUP_KEY")

    def test_escaped_duplicate_key_flagged(self):
        case = self.cases["escaped-duplicate-key"]
        self.assertEqual(case["verdict"], "risky")
        tenant = self.diff_of("escaped-duplicate-key", "tenant")
        self.assertEqual(tenant["classification"], "value_diff")
        self.assertEqual(tenant["gateway"]["value"], "acme")
        self.assertEqual(tenant["service"]["value"], "evil")
        self.assertEqual(case["canonical"]["error"]["code"], "E_DUP_KEY")

    def test_type_confusion_flagged(self):
        case = self.cases["dup-tenant-type"]
        self.assertEqual(case["verdict"], "risky")
        tenant = self.diff_of("dup-tenant-type", "tenant")
        self.assertEqual(tenant["classification"], "type_diff")

    def test_amount_above_2p53_flagged_and_out_of_range(self):
        case = self.cases["amount-2p53-plus1"]
        self.assertEqual(case["verdict"], "risky")
        amount = self.diff_of("amount-2p53-plus1", "amount")
        self.assertEqual(amount["classification"], "value_diff")
        self.assertEqual(amount["gateway"]["value"], "9007199254740993")
        self.assertEqual(amount["service"]["value"], "9007199254740992.0")
        self.assertEqual(case["canonical"]["error"]["code"], "E_RANGE")

    def test_serialization_only_dup_not_risky_but_rejected(self):
        case = self.cases["serialization-only-dup"]
        self.assertEqual(case["verdict"], "rejected-by-canonicalization")
        self.assertFalse(case["authorization_risk"])
        amount = self.diff_of("serialization-only-dup", "amount")
        self.assertEqual(amount["classification"], "serialization_only")
        self.assertFalse(amount["dangerous"])

    def test_bad_utf8_reports_byte_offset(self):
        case = self.cases["bad-utf8"]
        self.assertEqual(case["verdict"], "rejected-unparseable")
        error = case["parse"]["error"]
        self.assertEqual(error["code"], "E_UTF8")
        raw = (PROJECT_ROOT / "samples" / "bad-utf8.bin").read_bytes()
        self.assertEqual(error["offset"], raw.index(b"\xff"))

    def test_lone_surrogate_rejected(self):
        case = self.cases["lone-surrogate"]
        self.assertEqual(case["parse"]["error"]["code"], "E_UNICODE")

    def test_deep_nesting_rejected(self):
        case = self.cases["deep-nesting"]
        self.assertEqual(case["parse"]["error"]["code"], "E_DEPTH")

    def test_trailing_data_rejected(self):
        case = self.cases["trailing-data"]
        self.assertEqual(case["parse"]["error"]["code"], "E_SYNTAX")

    def test_inline_case_passes(self):
        case = self.cases["inline-demo"]
        self.assertEqual(case["verdict"], "pass")
        self.assertEqual(case["canonical"]["utf8"],
                         '{"amount":42,"role":"user","tenant":"acme"}')

    def test_fixed_seed_replay_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            second = Path(tmp) / "result2.json"
            rc, _ = run_cli(second)
            self.assertEqual(rc, 0)
            self.assertEqual(self.output.read_bytes(), second.read_bytes())


class TestCliInputValidation(unittest.TestCase):
    def test_missing_input_file_returns_2(self):
        rc = main(["--input", "no-such-file.json", "--output", "x.json"])
        self.assertEqual(rc, 2)

    def test_bad_case_definition_reported_not_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "cases.json"
            spec.write_text(json.dumps({"cases": [{"name": "broken"}]}),
                            encoding="utf-8")
            out = Path(tmp) / "result.json"
            rc = main(["--input", str(spec), "--output", str(out)])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            case = report["cases"][0]
            self.assertEqual(case["verdict"], "error")
            self.assertEqual(case["case_error"]["code"], "E_SCHEMA")
            self.assertEqual(report["summary"]["errors"], 1)


if __name__ == "__main__":
    unittest.main()
