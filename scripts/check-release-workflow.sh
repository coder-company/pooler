#!/usr/bin/env bash
# Validate the release workflow's safety-critical dependency wiring.

set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python3 "$ROOT/scripts/tests/test_release_safety.py"
exec python3 "$ROOT/scripts/check-release-workflow.py" "$@"
