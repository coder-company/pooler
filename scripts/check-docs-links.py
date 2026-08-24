#!/usr/bin/env python3
"""Check that documentation links resolve and code fences reference real things."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def slug(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[\s_]+", "-", text)


def anchors(path: Path) -> set[str]:
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            found.add(slug(line.lstrip("#")))
        matched = re.search(r'<h[1-6][^>]*>(.*?)</h[1-6]>', line)
        if matched:
            found.add(slug(re.sub(r"<[^>]+>", "", matched.group(1))))
    return found


def main() -> int:
    targets = [
        *sorted(ROOT.glob("*.md")),
        ROOT / "llms.txt",
        *sorted((ROOT / "docs").glob("*.md")),
    ]
    failures: list[str] = []

    for source in targets:
        text = source.read_text(encoding="utf-8")
        for target in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_part, _, anchor = target.partition("#")
            if not path_part:
                if anchor and anchor not in anchors(source):
                    failures.append(f"{source.relative_to(ROOT)}: missing anchor #{anchor}")
                continue
            resolved = (source.parent / path_part).resolve()
            if not resolved.exists():
                failures.append(f"{source.relative_to(ROOT)}: missing file {path_part}")
            elif anchor and resolved.suffix == ".md" and anchor not in anchors(resolved):
                failures.append(f"{source.relative_to(ROOT)}: missing anchor {path_part}#{anchor}")

    for problem in failures:
        print(f"FAIL {problem}")
    print(f"checked {len(targets)} documents, {len(failures)} problems")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
