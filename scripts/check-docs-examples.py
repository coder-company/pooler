#!/usr/bin/env python3
"""Validate documentation against the shipped binary.

Two checks run. Every fenced yaml block that declares a top-level `version:` is
compiled with `pooler check`; blocks without one are deliberate fragments and
are skipped. Every documented "N known providers" claim is compared against
`pooler providers --json` so the advertised count cannot drift from the build.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FENCE = re.compile(r"```ya?ml\n(.*?)```", re.DOTALL)
PROVIDER_CLAIM = re.compile(r"\*{0,2}(\d[\d,]*)\*{0,2}\s+known providers")


def documented_sources() -> list[Path]:
    return [
        ROOT / "README.md",
        ROOT / "llms.txt",
        *sorted((ROOT / "docs").glob("*.md")),
    ]


def check_provider_count(binary: Path) -> list[str]:
    """Compare every documented provider count with the shipped catalog."""
    result = subprocess.run(
        [str(binary), "providers", "--json"], capture_output=True, text=True
    )
    if result.returncode != 0:
        return [f"pooler providers --json failed: {result.stderr.strip()}"]
    actual = len(json.loads(result.stdout)["providers"])

    failures = []
    claims = 0
    for source in documented_sources():
        for claimed in PROVIDER_CLAIM.findall(source.read_text(encoding="utf-8")):
            claims += 1
            if int(claimed.replace(",", "")) != actual:
                failures.append(
                    f"{source.relative_to(ROOT)}: claims {claimed} known providers, "
                    f"build ships {actual}"
                )
    if claims == 0:
        failures.append(
            f"no documentation states the provider count; build ships {actual}"
        )
    else:
        print(f"verified {claims} provider-count claims against {actual} providers")
    return failures


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

    sources = documented_sources()
    checked = 0
    failures: list[str] = check_provider_count(binary)

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
