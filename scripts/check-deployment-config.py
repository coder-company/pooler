#!/usr/bin/env python3
"""Validate the compiled canonical production seed.

The seed exposes only loopback listeners and management authentication. The
dashboard adds providers and explicit routes after installation.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

try:
    import yaml
except ImportError as error:  # pragma: no cover - exercised by the runner
    raise SystemExit("deployment config check requires PyYAML") from error


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "deploy" / "pooler.example.yaml"

# The deployment pins provider: openai. These are the 33 OpenAI surfaces the
# gateway loader publishes from its 47 protocol declarations; Anthropic and
# Gemini-only declarations are intentionally filtered before compilation.
EXPECTED_BINDS = {
    "inference": "127.0.0.1:18400",
    "management": "127.0.0.1:18401",
}


def render_config() -> str:
    pooler_bin = os.environ.get("POOLER_BIN")
    if pooler_bin:
        command = [pooler_bin]
    else:
        command = ["cargo", "run", "--locked", "-p", "pooler-cli", "--"]
    command.extend(["--config", str(CONFIG), "config", "render"])
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"could not render {CONFIG}: exit {result.returncode}")
    return result.stdout


def main() -> int:
    try:
        document = yaml.safe_load(render_config())
    except yaml.YAMLError as error:
        print(f"compiled deployment YAML is invalid: {error}", file=sys.stderr)
        return 1

    if not isinstance(document, dict):
        print("compiled deployment config must be a mapping", file=sys.stderr)
        return 1
    listeners = document.get("listeners")
    inference = listeners.get("inference") if isinstance(listeners, dict) else None
    if not isinstance(inference, dict) or inference.get("bind") != EXPECTED_BINDS["inference"]:
        print("deployment inference listener must use the canonical loopback bind", file=sys.stderr)
        return 1
    management = document.get("management")
    auth = management.get("auth") if isinstance(management, dict) else None
    if not isinstance(management, dict) or management.get("bind") != EXPECTED_BINDS["management"]:
        print("deployment management listener must use the canonical loopback bind", file=sys.stderr)
        return 1
    if not isinstance(auth, dict) or auth.get("secret") != "file:/etc/pooler/management.key":
        print("deployment management authentication must use its owner-private file", file=sys.stderr)
        return 1
    routes = document.get("routes", [])
    if routes != []:
        print("deployment seed must not publish inference routes before dashboard enrollment", file=sys.stderr)
        return 1

    print("validated canonical loopback-only deployment seed and management authentication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
