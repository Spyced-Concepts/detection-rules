#!/usr/bin/env python3
# Copyright 2026 Spyced Concepts Ltd. (company number 16978283)
# SPDX-License-Identifier: Apache-2.0
"""
Import specific files into the test container, run tests, export results.
No bind mounts. No external dependencies — stdlib only.

Usage (run from anywhere):
    python tests/run.py <service> --in-dir <dir> [--out-dir <dir>]
    python tests/run.py <service> --in <src>:<dest> [--in ...] [--out-dir <dir>]

Arguments:
    --in-dir DIR      Copy DIR into /input/ inside the container
    --in SRC:DEST     Copy SRC (host) into DEST (container). Repeatable.
    --out-dir DIR     Where to save results on the host (default: tests/results/)

Examples:
    python tests/run.py sigma-tests --in-dir megalodon/sigma
    python tests/run.py sigma-tests --in-dir megalodon/sigma --out-dir tests/megalodon/results
    python tests/run.py yara-tests
        --in megalodon/yara:/input/megalodon/yara
        --in tests/megalodon:/input/tests/megalodon

To add a new service: add an entry to SERVICES and document it in TESTING.md.
"""

import argparse
import datetime
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
IMAGE = "detection-rules-tests"

def _dated(label):
    return f"{label}-{datetime.date.today().isoformat()}.txt"


SERVICES = {
    "yara-tests": {
        "cmd": [
            "python3", "/tests/yara-score.py",
            "/input/test/yara/test-manifest.json",
            "--root", "/input",
            "--output", f"/output/{_dated('yara')}",
        ],
        "hint": "python tests/run.py yara-tests --in-dir megalodon --out-dir megalodon/test/yara/results",
    },
    "sigma-tests": {
        "cmd": [
            "python3", "/tests/sigma-convert.py",
            "--rules-dir", "/input/sigma",
            "--output", f"/output/{_dated('sigma')}",
        ],
        "hint": "python tests/run.py sigma-tests --in-dir megalodon --out-dir megalodon/test/sigma/results",
    },
}


def _run(cmd, **kwargs):
    return subprocess.run(cmd, **kwargs)


def build(service):
    result = _run(["docker", "compose", "build", service], cwd=SCRIPT_DIR)
    if result.returncode != 0:
        sys.exit(result.returncode)


def create(container, image, cmd):
    result = _run(
        ["docker", "create", "--name", container, image] + cmd,
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: docker create failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)


def copy_in(container, src: Path, dest: str):
    # Append /. to copy directory contents rather than the directory itself.
    # Use as_posix() so Docker receives forward slashes on all platforms.
    src_arg = src.as_posix() + "/."
    result = _run(["docker", "cp", src_arg, f"{container}:{dest.rstrip('/')}/"])
    if result.returncode != 0:
        print(f"ERROR: failed to copy {src} -> container:{dest}", file=sys.stderr)
        sys.exit(1)


def start(container):
    _run(["docker", "start", "--attach", container])
    inspect = _run(
        ["docker", "inspect", container, "--format", "{{.State.ExitCode}}"],
        capture_output=True, text=True,
    )
    try:
        return int(inspect.stdout.strip())
    except ValueError:
        return 1


def copy_out(container, src: str, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    # Append /. to copy contents of the container directory, not the dir itself.
    result = _run(["docker", "cp", f"{container}:{src.rstrip('/')}/.", str(dest)])
    if result.returncode != 0:
        print(f"WARNING: failed to copy container:{src} -> {dest}", file=sys.stderr)


def remove(container):
    _run(["docker", "rm", "-f", container], capture_output=True)


def main():
    parser = argparse.ArgumentParser(
        description="Run detection-rule tests in Docker with explicit file import/export.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("service", choices=list(SERVICES), help="Test service to run")
    parser.add_argument(
        "--in-dir", metavar="DIR",
        help="Copy DIR into /input/ inside the container",
    )
    parser.add_argument(
        "--in", dest="inputs", action="append", default=[], metavar="SRC:DEST",
        help="Copy SRC (host) into DEST (container). Repeatable.",
    )
    parser.add_argument(
        "--out-dir", metavar="DIR",
        default=str(SCRIPT_DIR / "results"),
        help="Where to save results on the host (default: tests/results/)",
    )
    args = parser.parse_args()

    inputs = list(args.inputs)
    if args.in_dir:
        inputs.append(f"{args.in_dir}:/input")

    if not inputs:
        cfg = SERVICES[args.service]
        print("ERROR: no input paths specified.", file=sys.stderr)
        print(f"\nTypical usage:\n    {cfg['hint']}", file=sys.stderr)
        sys.exit(1)

    cfg = SERVICES[args.service]
    out_dir = Path(args.out_dir)
    container = f"{args.service}-{int(time.time())}-{os.getpid()}"

    print("==> Building image (detection-rules-tests)...")
    build(args.service)

    print("==> Creating container...")
    create(container, IMAGE, cfg["cmd"])

    exit_code = 1
    try:
        print("==> Importing input files...")
        for pair in inputs:
            if ":" not in pair:
                print(f"ERROR: --in value must be SRC:DEST, got: {pair!r}", file=sys.stderr)
                sys.exit(1)
            src_str, dest = pair.split(":", 1)
            src = Path(src_str)
            if not src.is_absolute():
                src = REPO_ROOT / src
            if not src.exists():
                print(f"ERROR: source path does not exist: {src}", file=sys.stderr)
                sys.exit(1)
            print(f"    {src_str}  ->  container:{dest}")
            copy_in(container, src, dest)

        print(f"==> Running {args.service}...")
        exit_code = start(container)

        print("==> Exporting results...")
        copy_out(container, "/output/", out_dir)
        print(f"    Results saved to: {out_dir}")

    finally:
        remove(container)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
