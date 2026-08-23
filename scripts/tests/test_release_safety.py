#!/usr/bin/env python3
"""Behavioral safety tests for the release packager."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts" / "release.sh"


class ReleaseSafetyTests(unittest.TestCase):
    def test_existing_release_artifact_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            existing = output / "pooler-existing.tar.gz"
            existing.write_bytes(b"keep me")

            result = subprocess.run(
                [
                    str(RELEASE),
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--output",
                    str(output),
                    "--epoch",
                    "0",
                    "--binary",
                    sys.executable,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release output already contains an artifact", result.stderr)
            self.assertEqual(existing.read_bytes(), b"keep me")
            self.assertEqual(sorted(output.iterdir()), [existing])


if __name__ == "__main__":
    unittest.main()
