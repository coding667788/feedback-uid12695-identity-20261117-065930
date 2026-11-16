"""CLI entry point: python -m solution --input cases.json --output result.json

cases.json schema (version 1):

    {
      "version": 1,
      "protected_paths": ["tenant", "amount", "role"],   // optional
      "max_depth": 128,                                  // optional
      "cases": [
        {"name": "...", "file": "samples/x.json"},        // bytes from file
        {"name": "...", "inline": "{\"a\": 1}"}           // UTF-8 string
      ]
    }

``file`` paths are resolved relative to the cases.json directory and are
always read as raw bytes (so binary/invalid-UTF-8 samples work). The output
document is deterministic: no timestamps, no randomness, fixed HMAC seed.
"""

import argparse
import json
import sys
from pathlib import Path

from .audit import DEFAULT_PROTECTED_PATHS, analyze_bytes
from .errors import CaseError
from .parser import DEFAULT_MAX_DEPTH
from .signature import SEED

TOOL_NAME = "json-sig-boundary-audit"
SCHEMA_VERSION = 1


def load_case_bytes(entry: dict, base_dir: Path):
    has_file = "file" in entry
    has_inline = "inline" in entry
    if has_file == has_inline:
        raise CaseError("E_SCHEMA", "case must set exactly one of 'file' or 'inline'")
    if has_inline:
        value = entry["inline"]
        if not isinstance(value, str):
            raise CaseError("E_SCHEMA", "'inline' must be a JSON string")
        return value.encode("utf-8"), {"type": "inline"}
    rel = entry["file"]
    if not isinstance(rel, str):
        raise CaseError("E_SCHEMA", "'file' must be a string path")
    path = (base_dir / rel).resolve()
    try:
        return path.read_bytes(), {"type": "file", "path": rel}
    except OSError as exc:
        raise CaseError("E_IO", f"cannot read case file {rel!r}: {exc}") from exc


def run(spec: dict, base_dir: Path, cli_max_depth: int) -> dict:
    if not isinstance(spec, dict) or not isinstance(spec.get("cases"), list):
        raise CaseError("E_SCHEMA", "input must be an object with a 'cases' array")
    protected_paths = spec.get("protected_paths", DEFAULT_PROTECTED_PATHS)
    max_depth = int(spec.get("max_depth", cli_max_depth))

    cases = []
    for entry in spec["cases"]:
        name = entry.get("name", "<unnamed>") if isinstance(entry, dict) else "<invalid>"
        try:
            if not isinstance(entry, dict):
                raise CaseError("E_SCHEMA", "case entry must be an object")
            data, source = load_case_bytes(entry, base_dir)
            result = analyze_bytes(data, name=name, source=source,
                                   protected_paths=protected_paths,
                                   max_depth=max_depth)
        except CaseError as exc:
            result = {"name": name, "case_error": exc.to_dict(),
                      "authorization_risk": False, "verdict": "error"}
        cases.append(result)

    summary = {
        "total": len(cases),
        "pass": sum(1 for c in cases if c["verdict"] == "pass"),
        "risky": sum(1 for c in cases if c["verdict"] == "risky"),
        "rejected": sum(1 for c in cases if c["verdict"].startswith("rejected")),
        "errors": sum(1 for c in cases if c["verdict"] == "error"),
    }
    return {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "seed": SEED.decode("ascii"),
        "policies": {
            "gateway": {"object": "first-key", "number": "exact-integer"},
            "service": {"object": "last-key", "number": "ieee754"},
        },
        "protected_paths": protected_paths,
        "max_depth": max_depth,
        "canonical_rules": {
            "encoding": "utf-8",
            "key_order": "unicode-code-point",
            "whitespace": "none",
            "numbers": "integers with |v| <= 2^53-1; -0 normalized to 0",
            "duplicate_keys": "rejected at every nesting level",
        },
        "cases": cases,
        "summary": summary,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Audit authorization risk from divergent JSON parsing "
                    "between a gateway and a business service.")
    parser.add_argument("--input", required=True, help="path to cases.json")
    parser.add_argument("--output", required=True, help="path to write result.json")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                        help="nesting limit (default %(default)s)")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    try:
        spec = json.loads(input_path.read_text(encoding="utf-8"))
        report = run(spec, input_path.resolve().parent, args.max_depth)
    except CaseError as exc:
        print(f"input error [{exc.code}]: {exc.message}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        print(f"input error [E_IO]: {exc}", file=sys.stderr)
        return 2

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    summary = report["summary"]
    print(f"analyzed {summary['total']} case(s): "
          f"{summary['pass']} pass, {summary['risky']} risky, "
          f"{summary['rejected']} rejected, {summary['errors']} error(s) "
          f"-> {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
