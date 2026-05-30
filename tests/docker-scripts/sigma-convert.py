#!/usr/bin/env python3
# Copyright 2026 Spyced Concepts Ltd. (company number 16978283)
# SPDX-License-Identifier: Apache-2.0
"""
Sigma rule conversion test script.

Converts all Sigma rules to multiple backends and reports the results for
review. This tests that rules convert without error and produces the converted
queries for manual inspection of detection logic correctness.

Note: this is conversion testing, not FP/FN detection testing. Sigma rules
target log events; fixture-based detection testing requires log event corpora
not yet implemented. See TESTING.md for the documented gap.

Usage:
    python3 tests/run-sigma-tests.py
    python3 tests/run-sigma-tests.py --backends splunk elasticsearch
    python3 tests/run-sigma-tests.py --output /results/2026-05-30-sigma.txt

Exit codes:
    0 — all conversions passed
    1 — one or more conversions failed
    2 — sigma binary not found or no rules found
"""

import argparse
import subprocess
import sys
from pathlib import Path


DEFAULT_RULES_DIR = Path("/input")
DEFAULT_BACKENDS = ["splunk", "lucene", "opensearch_lucene"]


class Tee:
    def __init__(self, path=None):
        self._lines = []
        self._path = path

    def out(self, text=""):
        print(text)
        self._lines.append(str(text))

    def flush(self):
        if self._path:
            out_path = Path(self._path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text("\n".join(self._lines) + "\n")
            print(f"\nReport saved: {self._path}", file=sys.stderr)


def sigma_available():
    result = subprocess.run(["sigma", "version"], capture_output=True, text=True)
    return result.returncode == 0


def convert_rule(rule_path, backend):
    """Run sigma convert for a single rule and backend. Returns (ok, output, error)."""
    result = subprocess.run(
        ["sigma", "convert", "-t", backend, "--without-pipeline", str(rule_path)],
        capture_output=True,
        text=True,
    )
    ok = result.returncode == 0 and bool(result.stdout.strip())
    return ok, result.stdout.strip(), result.stderr.strip()


def main():
    parser = argparse.ArgumentParser(description="Sigma rule conversion tests")
    parser.add_argument(
        "--rules-dir",
        default=str(DEFAULT_RULES_DIR),
        metavar="DIR",
        help=f"Directory containing Sigma rule YAML files (default: {DEFAULT_RULES_DIR})",
    )
    parser.add_argument(
        "--backends",
        nargs="+",
        default=DEFAULT_BACKENDS,
        metavar="BACKEND",
        help=f"Backends to test (default: {' '.join(DEFAULT_BACKENDS)})",
    )
    parser.add_argument("--output", metavar="PATH", help="Save report to file")
    args = parser.parse_args()

    tee = Tee(args.output)

    if not sigma_available():
        tee.out("ERROR: sigma binary not found in PATH")
        tee.flush()
        sys.exit(2)

    rules_dir = Path(args.rules_dir)
    rules = sorted(rules_dir.glob("*.yml"))
    if not rules:
        tee.out(f"ERROR: no Sigma rules found in {rules_dir}")
        tee.flush()
        sys.exit(2)

    tee.out("=" * 72)
    tee.out("SIGMA RULE CONVERSION TEST")
    tee.out("Spyced Concepts Ltd. | detection-rules | megalodon campaign")
    tee.out("=" * 72)
    tee.out(f"Rules dir   : {rules_dir}")
    tee.out(f"Rules found : {len(rules)}")
    tee.out(f"Backends    : {', '.join(args.backends)}")
    tee.out("")
    tee.out("NOTE: This is conversion testing only. Sigma rules are validated by")
    tee.out("converting them to SIEM query languages and reviewing the output.")
    tee.out("FP/FN fixture-based detection testing for Sigma is not yet implemented.")
    tee.out("See TESTING.md for the documented gap.")
    tee.out("")

    passed = 0
    failed = 0
    no_output = 0

    for rule_path in rules:
        tee.out("─" * 72)
        tee.out(f"RULE: {rule_path.name}")
        tee.out("")

        for backend in args.backends:
            ok, output, error = convert_rule(rule_path, backend)

            if ok:
                tee.out(f"  [{backend}] PASS")
                for line in output.splitlines():
                    tee.out(f"    {line}")
                tee.out("")
                passed += 1
            elif result_is_empty := (not output and not error):
                tee.out(f"  [{backend}] NO OUTPUT — backend may lack logsource mapping for this rule")
                tee.out("")
                no_output += 1
            else:
                tee.out(f"  [{backend}] FAIL")
                if error:
                    for line in error.splitlines():
                        tee.out(f"    ERROR: {line}")
                if output:
                    for line in output.splitlines():
                        tee.out(f"    OUT:   {line}")
                tee.out("")
                failed += 1

    total = passed + failed + no_output
    tee.out("=" * 72)
    tee.out("SUMMARY")
    tee.out("=" * 72)
    tee.out(f"Rules tested      : {len(rules)}")
    tee.out(f"Backends tested   : {len(args.backends)}")
    tee.out(f"Total conversions : {total}")
    tee.out(f"  Passed          : {passed}")
    tee.out(f"  No output       : {no_output}  (logsource not mapped for backend)")
    tee.out(f"  Failed          : {failed}")
    tee.out("")

    if failed == 0 and no_output == 0:
        tee.out("RESULT: ALL CONVERSIONS PASSED")
    elif failed == 0:
        tee.out(f"RESULT: PASSED WITH GAPS — {no_output} logsource mapping(s) missing")
    else:
        tee.out(f"RESULT: FAILED — {failed} conversion error(s)")

    tee.flush()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
