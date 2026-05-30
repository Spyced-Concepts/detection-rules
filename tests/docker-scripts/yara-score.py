#!/usr/bin/env python3
# Copyright 2026 Spyced Concepts Ltd. (company number 16978283)
# SPDX-License-Identifier: Apache-2.0
"""
YARA rule reliability scorer.

Reads a test manifest, runs YARA against each fixture, computes TP/FP/FN/TN
per rule, and reports precision, recall, F1, and Fβ.

Usage:
    python3 tests/run-tests.py tests/megalodon/test-manifest.json
    python3 tests/run-tests.py tests/megalodon/test-manifest.json --beta 2
    python3 tests/run-tests.py tests/megalodon/test-manifest.json --output /results/2026-05-30-score.txt

Exit codes:
    0 — all fixtures passed (no FP, no FN)
    1 — one or more fixtures failed
    2 — YARA binary not found or rules file missing
"""

import json
import subprocess
import sys
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


def fbeta_score(precision, recall, beta):
    denom = beta**2 * precision + recall
    if denom == 0:
        return 0.0
    return (1 + beta**2) * precision * recall / denom


def score_rule(rule, fixture_results, beta):
    """Compute TP/FP/FN/TN, precision, recall, F1, and Fβ for a single rule."""
    tp = fp = fn = tn = 0
    fp_files = []
    fn_files = []

    for r in fixture_results:
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
    fb = fbeta_score(precision, recall, beta)

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fbeta": fb,
        "fp_files": fp_files, "fn_files": fn_files,
    }


class Tee:
    """Write to stdout and optionally to a file."""

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


def main():
    import argparse
    parser = argparse.ArgumentParser(description="YARA rule reliability scorer")
    parser.add_argument("manifest", help="Path to test-manifest.json")
    parser.add_argument("--yara-bin", default="yara", help="Path to YARA binary (default: yara)")
    parser.add_argument(
        "--root", default=None, metavar="DIR",
        help="Repository root for resolving rules_file paths in the manifest. "
             "Default: two directories above this script (repo root when run locally).",
    )
    parser.add_argument(
        "--beta", type=float, default=2.0,
        help="β for Fβ scoring. β > 1 penalises false negatives more heavily (default: 2.0).",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="Write full report to this file path in addition to stdout.",
    )
    args = parser.parse_args()
    beta = args.beta

    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(2)

    manifest = json.loads(manifest_path.read_text())
    repo_root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    rules_file = repo_root / manifest["rules_file"]
    fixture_base = manifest_path.parent
    all_rules = manifest.get("all_rules", [])

    if not rules_file.exists():
        print(f"ERROR: rules file not found: {rules_file}", file=sys.stderr)
        sys.exit(2)

    try:
        subprocess.run([args.yara_bin, "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"ERROR: YARA binary not found or not executable: {args.yara_bin}", file=sys.stderr)
        print("Or run via Docker: see TESTING.md", file=sys.stderr)
        sys.exit(2)

    compile_result = subprocess.run(
        [args.yara_bin, str(rules_file), "/dev/null"],
        capture_output=True, text=True,
    )
    if compile_result.returncode != 0:
        print(f"ERROR: rules file failed to compile:\n{compile_result.stderr}", file=sys.stderr)
        sys.exit(2)

    tee = Tee(args.output)
    o = tee.out

    o(f"\n=== YARA Rule Reliability Test — {manifest['campaign']} ===\n")
    o(f"Rules:    {rules_file.relative_to(repo_root)}")
    positive_count = sum(1 for f in manifest["fixtures"] if f["expected_rules"])
    negative_count = sum(1 for f in manifest["fixtures"] if not f["expected_rules"])
    o(f"Fixtures: {len(manifest['fixtures'])} ({positive_count} positive, {negative_count} negative)")
    beta_label = f"F{beta:g}"
    o(f"Scoring:  {beta_label} (β={beta:g})")
    o()

    o("--- Scoring methodology ---")
    o()
    o("  Precision = TP / (TP + FP)")
    o("    Fraction of rule fires that are genuine matches.")
    o("    Low precision → false alarms erode analyst confidence.")
    o()
    o("  Recall = TP / (TP + FN)")
    o("    Fraction of genuinely malicious fixtures caught by the rule.")
    o("    Low recall → threats pass through undetected.")
    o()
    o("  F1 = 2 × Precision × Recall / (Precision + Recall)")
    o("    Harmonic mean. Treats a missed threat (FN) and a false alarm (FP) as equally costly.")
    o()
    o(f"  {beta_label} = (1 + β²) × Precision × Recall / (β² × Precision + Recall)   [β = {beta:g}]")
    if beta > 1:
        o(f"    β > 1: recall weighted more heavily. A missed threat is penalised {beta**2:g}× more than a false alarm.")
        o(f"    Rationale: in detection contexts a missed threat may allow an attack to proceed;")
        o(f"    a false alarm costs analyst time but does not allow the attack through.")
    elif beta < 1:
        o(f"    β < 1: precision weighted more heavily. A false alarm is penalised more than a missed threat.")
        o(f"    Use this when alert fatigue is the dominant risk (very high-volume, noisy environment).")
    else:
        o("    β = 1: F1 and Fβ are identical — equal weight to FP and FN.")
    o()
    o("  Publication requirement: Precision = 1.00, Recall = 1.00, F1 = 1.00, Fβ = 1.00")
    o("  Zero FP and zero FN are the only inputs that satisfy all four metrics simultaneously.")
    o()

    fixture_results = []
    for spec in manifest["fixtures"]:
        fixture_file = fixture_base / spec["file"]
        if not fixture_file.exists():
            print(f"WARNING: fixture not found, skipping: {spec['file']}", file=sys.stderr)
            continue

        expected = set(spec["expected_rules"])
        actual, _ = run_yara(args.yara_bin, rules_file, fixture_file)

        unexpected = actual - expected
        missed = expected - actual
        passed = not unexpected and not missed

        fixture_results.append({
            "file": spec["file"],
            "description": spec.get("description", ""),
            "expected": expected,
            "actual": actual,
            "passed": passed,
            "unexpected": unexpected,
            "missed": missed,
            "fp_risk": spec.get("false_positive_risk", ""),
        })

    o("--- Fixture Results ---")
    o()
    passes = sum(1 for r in fixture_results if r["passed"])
    total = len(fixture_results)

    for r in fixture_results:
        status = "PASS" if r["passed"] else "FAIL"
        fixture_type = "positive" if r["expected"] else "negative"
        fp_label = f"  [FP-RISK:{r['fp_risk']}]" if r["fp_risk"] else ""
        o(f"  [{status}] [{fixture_type}] {r['file']}{fp_label}")
        if r["unexpected"]:
            o(f"         FALSE POSITIVE (unexpected match): {', '.join(sorted(r['unexpected']))}")
        if r["missed"]:
            o(f"         FALSE NEGATIVE (missed match):     {', '.join(sorted(r['missed']))}")

    o()
    o(f"  {passes}/{total} fixtures passed")
    o()

    o("--- Per-Rule Scores ---")
    o()
    col = 52
    header = (
        f"  {'Rule':<{col}} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
        f" {'Precision':>10} {'Recall':>8} {'F1':>6} {beta_label:>6}  Status"
    )
    o(header)
    o("  " + "-" * (len(header) - 2))

    all_passed = True
    rule_scores = {}
    for rule in sorted(all_rules):
        s = score_rule(rule, fixture_results, beta)
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
        o(
            f"  {rule:<{col}} {s['tp']:>4} {s['fp']:>4} {s['fn']:>4} {s['tn']:>4}"
            f" {s['precision']:>10.1%} {s['recall']:>8.1%} {s['f1']:>6.2f} {s['fbeta']:>6.2f}{flag_str}"
        )

        for f in s["fp_files"]:
            o(f"    FP in: {f}")
        for f in s["fn_files"]:
            o(f"    FN in: {f}")

    total_tp = sum(s["tp"] for s in rule_scores.values())
    total_fp = sum(s["fp"] for s in rule_scores.values())
    total_fn = sum(s["fn"] for s in rule_scores.values())
    total_tn = sum(s["tn"] for s in rule_scores.values())
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0 else 0.0
    )
    overall_fb = fbeta_score(overall_precision, overall_recall, beta)

    o(
        f"\n  {'OVERALL':<{col}} {total_tp:>4} {total_fp:>4} {total_fn:>4} {total_tn:>4}"
        f" {overall_precision:>10.1%} {overall_recall:>8.1%} {overall_f1:>6.2f} {overall_fb:>6.2f}"
    )

    o()
    if all_passed and passes == total:
        o("  Result: ALL TESTS PASSED ✓")
    else:
        o("  Result: TESTS FAILED — review false positives/negatives above")
        if total_fp > 0:
            o(f"  Action: {total_fp} false positive(s) — narrow rule conditions or add filters")
        if total_fn > 0:
            o(f"  Action: {total_fn} false negative(s) — check pattern coverage, update fixtures")

    o()
    tee.flush()
    sys.exit(0 if (all_passed and passes == total) else 1)


if __name__ == "__main__":
    main()
