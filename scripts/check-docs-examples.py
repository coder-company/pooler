#!/usr/bin/env python3
"""Compile every complete configuration example embedded in the documentation.

A fenced yaml block is treated as a complete source configuration when it
declares a top-level `version:`. Fragments are skipped because they are
deliberately partial.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FENCE = re.compile(r"```ya?ml\n(.*?)```", re.DOTALL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-binary",
        action="store_true",
        help="Fail instead of skipping when the pooler binary is missing.",
    )
    arguments = parser.parse_args()

    binary = ROOT / "target" / "debug" / "pooler"
    if not binary.exists():
        message = f"{binary} not built; run cargo build -p pooler-cli --bin pooler"
        if arguments.require_binary:
            print(f"FAIL {message}")
            return 1
        print(f"SKIP: {message}")
        return 0

    sources = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    checked = 0
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as directory:
        for source in sources:
            for index, block in enumerate(FENCE.findall(source.read_text(encoding="utf-8"))):
                if not re.search(r"^version:", block, re.MULTILINE):
                    continue
                candidate = Path(directory) / f"{source.stem}-{index}.yaml"
                candidate.write_text(block, encoding="utf-8")
                result = subprocess.run(
                    [str(binary), "check", "--config", str(candidate)],
                    capture_output=True,
                    text=True,
                )
                checked += 1
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout).strip().splitlines()
                    failures.append(
                        f"{source.relative_to(ROOT)} block {index}: "
                        f"{detail[0] if detail else 'unknown error'}"
                    )

    for problem in failures:
        print(f"FAIL {problem}")
    print(f"compiled {checked} documented configurations, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
