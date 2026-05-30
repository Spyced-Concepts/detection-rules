#!/usr/bin/env python3
"""
YARA rule reliability scorer.

Reads a test manifest, runs YARA against each fixture, computes TP/FP/FN/TN
per rule, and reports precision, recall, and F1.

Usage:
    python3 tests/run-tests.py tests/megalodon/test-manifest.json
    python3 tests/run-tests.py tests/megalodon/test-manifest.json --yara-bin /usr/bin/yara

Exit codes:
    0 — all fixtures passed (no FP, no FN)
    1 — one or more fixtures failed
    2 — YARA binary not found or rules file missing
"""

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def run_yara(yara_bin, rules_file, fixture_file):
    """Run YARA against a single fixture. Returns (set of matched rule names, stderr string)."""
    result = subprocess.run(
        [yara_bin, str(rules_file), str(fixture_file)],
        capture_output=True,
        text=True,
    )
    matched = set()
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if parts:
            matched.add(parts[0])
    return matched, result.stderr.strip()


def score_rule(rule, fixtures_results, all_rules):
    """Compute TP/FP/FN/TN for a single rule across all fixture results."""
    tp = fp = fn = tn = 0
    fp_files = []
    fn_files = []

    for r in fixtures_results:
        expected_match = rule in r["expected"]
        actual_match = rule in r["actual"]

        if expected_match and actual_match:
            tp += 1
        elif not expected_match and actual_match:
            fp += 1
            fp_files.append(r["file"])
        elif expected_match and not actual_match:
            fn += 1
            fn_files.append(r["file"])
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "fp_files": fp_files, "fn_files": fn_files,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="YARA rule reliability scorer")
    parser.add_argument("manifest", help="Path to test-manifest.json")
    parser.add_argument("--yara-bin", default="yara", help="Path to YARA binary (default: yara)")
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(2)

    manifest = json.loads(manifest_path.read_text())
    repo_root = Path(__file__).resolve().parent.parent
    rules_file = repo_root / manifest["rules_file"]
    fixture_base = manifest_path.parent
    all_rules = manifest.get("all_rules", [])

    if not rules_file.exists():
        print(f"ERROR: rules file not found: {rules_file}", file=sys.stderr)
        sys.exit(2)

    # Verify YARA binary is available
    try:
        subprocess.run([args.yara_bin, "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"ERROR: YARA binary not found or not executable: {args.yara_bin}", file=sys.stderr)
        print("Install with: brew install yara  OR  apt-get install yara", file=sys.stderr)
        print("Or run via Docker: see TESTING.md", file=sys.stderr)
        sys.exit(2)

    # Compile check first
    compile_result = subprocess.run(
        [args.yara_bin, str(rules_file), "/dev/null"],
        capture_output=True, text=True
    )
    if compile_result.returncode != 0:
        print(f"ERROR: rules file failed to compile:\n{compile_result.stderr}", file=sys.stderr)
        sys.exit(2)

    print(f"\n=== YARA Rule Reliability Test — {manifest['campaign']} ===\n")
    print(f"Rules: {rules_file.relative_to(repo_root)}")
    print(f"Fixtures: {len(manifest['fixtures'])} ({sum(1 for f in manifest['fixtures'] if f['expected_rules'])} positive, "
          f"{sum(1 for f in manifest['fixtures'] if not f['expected_rules'])} negative)\n")

    # Run YARA against each fixture
    fixture_results = []
    for spec in manifest["fixtures"]:
        fixture_file = fixture_base / spec["file"]
        if not fixture_file.exists():
            print(f"WARNING: fixture not found, skipping: {spec['file']}")
            continue

        expected = set(spec["expected_rules"])
        actual, stderr = run_yara(args.yara_bin, rules_file, fixture_file)

        unexpected = actual - expected
        missed = expected - actual
        passed = (unexpected == set() and missed == set())

        fp_risk = spec.get("false_positive_risk", "")
        risk_label = f" [FP-RISK:{fp_risk}]" if fp_risk else ""

        fixture_results.append({
            "file": spec["file"],
            "description": spec.get("description", ""),
            "expected": expected,
            "actual": actual,
            "passed": passed,
            "unexpected": unexpected,
            "missed": missed,
            "fp_risk": fp_risk,
        })

    # Print fixture-level results
    print("--- Fixture Results ---\n")
    passes = sum(1 for r in fixture_results if r["passed"])
    total = len(fixture_results)

    for r in fixture_results:
        status = "PASS" if r["passed"] else "FAIL"
        fp_label = f"  [FP-RISK:{r['fp_risk']}]" if r["fp_risk"] else ""
        print(f"  [{status}] {r['file']}{fp_label}")
        if r["unexpected"]:
            print(f"         FALSE POSITIVE (unexpected match): {', '.join(sorted(r['unexpected']))}")
        if r["missed"]:
            print(f"         FALSE NEGATIVE (missed match):     {', '.join(sorted(r['missed']))}")

    print(f"\n  {passes}/{total} fixtures passed\n")

    # Per-rule scoring
    print("--- Per-Rule Scores ---\n")
    col = 52
    header = f"  {'Rule':<{col}} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Precision':>10} {'Recall':>8} {'F1':>6}  Status"
    print(header)
    print("  " + "-" * (len(header) - 2))

    all_passed = True
    rule_scores = {}
    for rule in sorted(all_rules):
        s = score_rule(rule, fixture_results, all_rules)
        rule_scores[rule] = s

        flags = []
        if s["fp"] > 0:
            flags.append(f"⚠ {s['fp']} FALSE POSITIVE(S)")
            all_passed = False
        if s["fn"] > 0:
            flags.append(f"⚠ {s['fn']} FALSE NEGATIVE(S)")
            all_passed = False
        if not flags:
            flags.append("✓")

        flag_str = "  " + ", ".join(flags)
        print(f"  {rule:<{col}} {s['tp']:>4} {s['fp']:>4} {s['fn']:>4} {s['tn']:>4} "
              f"{s['precision']:>10.1%} {s['recall']:>8.1%} {s['f1']:>6.2f}{flag_str}")

        if s["fp_files"]:
            for f in s["fp_files"]:
                print(f"    FP in: {f}")
        if s["fn_files"]:
            for f in s["fn_files"]:
                print(f"    FN in: {f}")

    # Overall summary
    total_tp = sum(s["tp"] for s in rule_scores.values())
    total_fp = sum(s["fp"] for s in rule_scores.values())
    total_fn = sum(s["fn"] for s in rule_scores.values())
    total_tn = sum(s["tn"] for s in rule_scores.values())
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    overall_f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)) if (overall_precision + overall_recall) > 0 else 0.0

    print(f"\n  {'OVERALL':<{col}} {total_tp:>4} {total_fp:>4} {total_fn:>4} {total_tn:>4} "
          f"{overall_precision:>10.1%} {overall_recall:>8.1%} {overall_f1:>6.2f}")

    print()
    if all_passed and passes == total:
        print("  Result: ALL TESTS PASSED ✓")
    else:
        print("  Result: TESTS FAILED — review false positives/negatives above")
        if total_fp > 0:
            print(f"  Action: {total_fp} false positive(s) — narrow rule conditions or add filters")
        if total_fn > 0:
            print(f"  Action: {total_fn} false negative(s) — check pattern coverage, update fixtures")

    print()
    sys.exit(0 if (all_passed and passes == total) else 1)


if __name__ == "__main__":
    main()
