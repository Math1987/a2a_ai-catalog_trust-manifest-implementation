#!/usr/bin/env python3
"""Run this Python CLI against public fixtures; never invoke a Rust verifier."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    raw = args.index.read_bytes()
    index = json.loads(raw)
    base = args.index.parent
    results = []
    for case in index["cases"]:
        trusted = case["trustedOperators"]
        if len(trusted) > 1:
            raise SystemExit("The offline CLI accepts one explicitly expected operator.")
        expected_operator = trusted[0] if trusted else "did:web:operator-not-in-fixture.example"
        command = [sys.executable, str(Path(__file__).with_name("verify_catalog.py")),
                   "--catalog", str(base / case["catalog"]),
                   "--did-document", str(base / case["didDocument"]),
                   "--expected-operator", expected_operator, "--now", case["now"]]
        if case["requireExpiry"]:
            command.append("--require-expiry")
        run = subprocess.run(command, capture_output=True, text=True, timeout=15)
        result = json.loads(run.stdout)
        accepted = result["success"] is True and run.returncode == 0
        passed = accepted == case["expectedAccepted"] and run.returncode in (0, 1)
        results.append({"id": case["id"], "expected_accepted": case["expectedAccepted"],
                        "python_accepted": accepted, "passed": passed,
                        "expected_operator": expected_operator, "python_result": result})
    report = {"success": all(result["passed"] for result in results),
              "checked_at": datetime.now(timezone.utc).isoformat(), "mode": "offline-fixtures",
              "vector_index_sha256": hashlib.sha256(raw).hexdigest(),
              "cases": len(results), "passed": sum(result["passed"] for result in results),
              "expected_accepts": sum(result["expected_accepted"] for result in results),
              "expected_rejects": sum(not result["expected_accepted"] for result in results),
              "empty_trust_policy_mapping": "A deliberately different expected operator is passed because the CLI requires one operator.",
              "results": results}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    for result in results:
        if not result["passed"]:
            print(json.dumps({"mismatch": result["id"], "result": result["python_result"]}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
