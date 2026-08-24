#!/usr/bin/env bash

# Scan only newly added Git content. Diagnostics identify a path and rule,
# never a matched line or candidate secret value.

set -Eeuo pipefail

usage() {
    printf '%s\n' 'usage: scripts/check-staged-secrets.sh [--commit COMMIT]' >&2
    exit 2
}

COMMIT=
while (($# > 0)); do
    case "$1" in
        --commit) (($# >= 2)) || usage; COMMIT=$2; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

file_list=$(mktemp /tmp/pooler-secret-files.XXXXXX)
scan_file=$(mktemp /tmp/pooler-secret-scan.XXXXXX)
trap 'rm -f -- "$file_list" "$scan_file"' EXIT HUP INT TERM

if [[ -n "$COMMIT" ]]; then
    git rev-parse --verify "$COMMIT^{commit}" >/dev/null 2>&1 ||
        { printf 'staged secret scan: unknown commit\n' >&2; exit 2; }
    git diff-tree --root --no-commit-id --name-only -r --diff-filter=ACMR -z "$COMMIT" >"$file_list"
else
    git diff --cached --name-only --diff-filter=ACMR -z >"$file_list"
fi

matches=0
while IFS= read -r -d '' path; do
    [[ -n "$path" ]] || continue
    if [[ -n "$COMMIT" ]]; then
        git diff-tree --root --no-commit-id --no-color --text --unified=0 "$COMMIT" -- "$path" >"$scan_file"
    else
        git diff --cached --no-color --text --unified=0 -- "$path" >"$scan_file"
    fi
    if python3 - "$path" "$scan_file" <<'PY'
import re
import sys
from pathlib import Path

path = sys.argv[1]
diff = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
added = "\n".join(
    line[1:]
    for line in diff.splitlines()
    if line.startswith("+") and not line.startswith("+++")
)

patterns = (
    ("api_key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ("private_key", r"-----BEGIN[ \t]+(?:RSA[ \t]+|EC[ \t]+|OPENSSH[ \t]+|DSA[ \t]+)?PRIVATE[ \t]+KEY-----"),
    ("oauth_refresh_token", r"(?i:\brefresh_token['\"]?[ \t]*[:=][ \t]*['\"]?[A-Za-z0-9._~+/=-]{20,})"),
    ("cookie", r"(?i:\b(?:cookie|set-cookie|session(?:_id)?|connect\.sid)['\"]?[ \t]*[:=][ \t]*(?:['\"][A-Za-z0-9._~+/=-]{20,}|(?=[A-Za-z0-9._~+/=-]{20,})(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{20,}))"),
    ("management_bearer", r"(?i:\b(?:management[_ -]?bearer|authorization)['\"]?[ \t]*[:=][ \t]*['\"]?Bearer[ \t]+[A-Za-z0-9._~+/=-]{20,})"),
    ("secret_assignment", r"(?i:\b(?:api[_ -]?key|client[_ -]?secret|management[_ -]?key)['\"]?[ \t]*[:=][ \t]*['\"][A-Za-z0-9._~+/=-]{20,})"),
)
safe_literals = (
    "sk-live-1234567890",
    "sk-secret-123456789",
    "ghp_abcdefghijklmnopqrstuvwxyz",
    "Bearer secret",
    "Bearer top-secret",
    "env-secret-value",
    "refresh-live-secret",
    "nested-password",
    "client-secret-value",
    "service-client-secret",
    "access-token-value",
    "private-cookie",
    "do-not-log-this",
    "split-secret-token",
    "proof-secret",
    "session-secret-value",
    "access-secret",
    "refresh-secret",
)

found = []
for rule, expression in patterns:
    match = re.search(expression, added)
    if match:
        if any(literal in match.group(0) for literal in safe_literals):
            continue
        found.append(rule)

for rule in sorted(set(found)):
    print(f"secret scan failed: {path} ({rule})")
raise SystemExit(bool(found))
PY
    then
        :
    else
        matches=$((matches + 1))
    fi
done <"$file_list"

if [[ "$matches" -ne 0 ]]; then
    exit 1
fi
printf '%s\n' 'staged secret scan passed (values redacted)'
