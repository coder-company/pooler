#!/usr/bin/env python3
"""Validate documentation against the shipped binary.

Three checks run. Every fenced yaml block that declares a top-level `version:`
is compiled with `pooler check`; blocks without one are deliberate fragments
and are skipped. Every documented "N known providers" claim is compared
against `pooler providers --json`. The schema's preset inventory must also be
represented in the README table, preset reference, and detailed preset sections.
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
README_PRESET = re.compile(r"^\| \[`([^`]+)`\]", re.MULTILINE)
REFERENCE_PRESET = re.compile(r"^\| `([^`]+)` \|", re.MULTILINE)
PRESET_HEADING = re.compile(r"^## `([^`]+)`$", re.MULTILINE)


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


def markdown_section(text: str, heading: str) -> str:
    """Return one level-two Markdown section without neighboring tables."""
    marker = f"## {heading}"
    start = text.find(marker)
    if start < 0:
        return ""
    start += len(marker)
    end = text.find("\n## ", start)
    return text[start:] if end < 0 else text[start:end]


def markdown_range(text: str, first_heading: str, final_heading: str) -> str:
    """Return text between two exact headings, excluding the final heading."""
    start = text.find(first_heading)
    if start < 0:
        return ""
    end = text.find(final_heading, start + len(first_heading))
    return text[start:] if end < 0 else text[start:end]


def preset_inventory_failures(
    presets: set[str], readme: str, guide: str
) -> list[str]:
    """Compare schema presets exactly with the three public inventories."""
    inventories = {
        "README preset table": set(
            README_PRESET.findall(markdown_section(readme, "Presets"))
        ),
        "preset reference table": set(
            REFERENCE_PRESET.findall(markdown_section(guide, "Preset reference"))
        ),
        "detailed preset sections": set(
            PRESET_HEADING.findall(
                markdown_range(guide, "## Client prerequisites", "## Verify a preset")
            )
        ),
    }
    failures = []
    for label, documented in inventories.items():
        missing = sorted(presets - documented)
        stale = sorted(documented - presets)
        if missing:
            failures.append(f"{label} omits schema presets: {', '.join(missing)}")
        if stale:
            failures.append(f"{label} advertises unknown presets: {', '.join(stale)}")
    return failures


def check_preset_inventory(binary: Path) -> list[str]:
    """Require every schema-advertised preset in each public inventory."""
    result = subprocess.run(
        [str(binary), "config", "schema"], capture_output=True, text=True
    )
    if result.returncode != 0:
        return [f"pooler config schema failed: {result.stderr.strip()}"]
    try:
        schema = json.loads(result.stdout)
        values = schema["$defs"]["import"]["oneOf"][2]["properties"]["preset"]["enum"]
        presets = {value for value in values if isinstance(value, str)}
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        return [f"could not read preset inventory from config schema: {error}"]
    if not presets:
        return ["config schema advertises no presets"]

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs/adapters-and-presets.md").read_text(encoding="utf-8")
    failures = preset_inventory_failures(presets, readme, guide)
    if not failures:
        print(f"verified {len(presets)} schema presets across public inventories")
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
    failures.extend(check_preset_inventory(binary))

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
