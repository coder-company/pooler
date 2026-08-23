#!/usr/bin/env python3
"""Validate the compiled deployment route authentication invariant.

The gateway preset intentionally filters its 47 protocol declarations by the
selected provider. This check validates the routes that the deployment
actually publishes after that filtering, rather than relying on a brittle
line-oriented scan of the source preset.
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
EXPECTED_ROUTE_IDS = {
    "gateway-models",
    "gateway-chat-completions",
    "gateway-completions",
    "gateway-embeddings",
    "gateway-files-list",
    "gateway-files-create",
    "gateway-files-content",
    "gateway-files-resource",
    "gateway-batches-list",
    "gateway-batches-create",
    "gateway-batches-cancel",
    "gateway-batches-resource",
    "gateway-responses",
    "gateway-responses-compact",
    "gateway-image-generations",
    "gateway-image-edits",
    "gateway-audio-transcriptions",
    "gateway-video-creations",
    "gateway-video-edits",
    "gateway-video-extensions",
    "gateway-video-remixes",
    "gateway-video-retrieval",
    "gateway-video-content",
    "gateway-video-deletions",
    "gateway-realtime-client-secrets",
    "gateway-realtime-sessions",
    "gateway-realtime-transcription-sessions",
    "gateway-realtime-calls-accept",
    "gateway-realtime-calls-reject",
    "gateway-realtime-calls-refer",
    "gateway-realtime-calls-hangup",
    "gateway-realtime-websocket",
    "gateway-responses-websocket",
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
    routes = document.get("routes")
    if not isinstance(listeners, dict) or not isinstance(routes, list) or not routes:
        print("compiled deployment config must contain listeners and routes", file=sys.stderr)
        return 1

    route_ids: set[str] = set()
    for route in routes:
        if not isinstance(route, dict):
            print("compiled deployment route is not a mapping", file=sys.stderr)
            return 1
        route_id = route.get("id")
        if not isinstance(route_id, str) or not route_id:
            print("compiled deployment route has no ID", file=sys.stderr)
            return 1
        if route_id in route_ids:
            print(f"duplicate compiled deployment route: {route_id}", file=sys.stderr)
            return 1
        route_ids.add(route_id)

        listener_id = route.get("listen", route.get("listener"))
        if not isinstance(listener_id, str) or listener_id not in listeners:
            print(f"{route_id}: listener {listener_id!r} is missing", file=sys.stderr)
            return 1
        auth = route.get("downstream_auth")
        if not isinstance(auth, dict):
            print(f"{route_id}: downstream authentication is missing", file=sys.stderr)
            return 1
        secret = auth.get("secret")
        if not isinstance(secret, str) or not any(
            secret.startswith(prefix) for prefix in ("env:", "file:", "keyring:")
        ):
            print(f"{route_id}: downstream auth must use a protected secret reference", file=sys.stderr)
            return 1

    if route_ids != EXPECTED_ROUTE_IDS:
        missing = sorted(EXPECTED_ROUTE_IDS - route_ids)
        unexpected = sorted(route_ids - EXPECTED_ROUTE_IDS)
        print(
            f"compiled deployment route set changed; missing={missing} unexpected={unexpected}",
            file=sys.stderr,
        )
        return 1

    print(
        f"validated {len(routes)} compiled deployment routes; "
        "every route requires downstream authentication"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
