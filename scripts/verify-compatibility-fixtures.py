#!/usr/bin/env python3
"""Run the executable verifier assigned to every compatibility-manifest row."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "fixtures/compatibility/manifest.json"


@dataclass(frozen=True)
class CargoTest:
    package: str
    source: str
    test_name: str
    target: str | None = None


@dataclass(frozen=True)
class ConfigCheck:
    pass


Verifier = CargoTest | ConfigCheck
EntryKey = tuple[str, str, str, str, str, str]


VERIFIERS: dict[EntryKey, Verifier] = {
    (
        "factory",
        "language-model-v3",
        "v3",
        "../factory/factory-v3-reference.json",
        "event_semantic",
        "sanitized_local_reference",
    ): CargoTest(
        package="adapter-factory",
        target="factory_bridge_fixture",
        source="crates/adapter-factory/tests/factory_bridge_fixture.rs",
        test_name="replays_factory_reference_request_and_semantic_stream",
    ),
    (
        "factory",
        "language-model-v3",
        "v3-text",
        "../factory/factory-v3-text-reference.json",
        "json_structural",
        "sanitized_local_reference",
    ): CargoTest(
        package="adapter-factory",
        target="factory_reference",
        source="crates/adapter-factory/tests/factory_reference.rs",
        test_name="replays_sanitized_factory_reference_request_and_stream",
    ),
    (
        "factory",
        "language-model-v4",
        "fx-0.0.3",
        "../factory/fx-0.0.3-v4-current-client.json",
        "event_semantic",
        "current_client_conformance",
    ): CargoTest(
        package="pooler-server",
        target="current_client_compatibility",
        source="crates/pooler-server/tests/current_client_compatibility.rs",
        test_name="factory_current_fixture_replays_through_http_proxy_server",
    ),
    (
        "devin",
        "connect-rpc",
        "v1",
        "../devin/connect/chat-stream.json",
        "protobuf_semantic",
        "sanitized_cross_language",
    ): CargoTest(
        package="adapter-devin",
        target="devin_fixtures",
        source="crates/adapter-devin/tests/devin_fixtures.rs",
        test_name="connect_fixture_covers_fragmentation_gzip_tools_identifiers_and_usage",
    ),
    (
        "devin",
        "connect-rpc",
        "3000.4.16",
        "../devin/current-client-tool-follow-up.json",
        "protobuf_semantic",
        "current_client_conformance",
    ): CargoTest(
        package="pooler-server",
        target="current_client_compatibility",
        source="crates/pooler-server/tests/current_client_compatibility.rs",
        test_name="devin_current_tool_follow_up_replays_through_http_proxy_server",
    ),
    (
        "fx",
        "ai-language-model-v4",
        "fx-0.0.3",
        "../fx/fx-0.0.3-tool-loop.json",
        "event_semantic",
        "sanitized_local_reference",
    ): CargoTest(
        package="adapter-fx",
        target="fx_tool_loop",
        source="crates/adapter-fx/tests/fx_tool_loop.rs",
        test_name="replays_streaming_tool_call_and_follow_up",
    ),
    (
        "cursor",
        "http-json-patch",
        "preset-v1",
        "../../config/cursor.example.yaml",
        "config_structural",
        "not_established",
    ): ConfigCheck(),
    (
        "cursor",
        "openai-compatible-chat",
        "2026.08.04-aaa8809",
        "../cursor/cursor-agent-local-2026.08.04.json",
        "json_structural",
        "current_client_conformance",
    ): CargoTest(
        package="pooler-server",
        source="crates/pooler-server/src/http_runtime.rs",
        test_name="cursor_current_fixture_replays_through_http_runtime",
    ),
    (
        "codex",
        "native-provider",
        "status-gated-v1",
        "../../config/pooler.example.yaml",
        "config_structural",
        "not_established",
    ): ConfigCheck(),
    (
        "codex",
        "openai-responses-websocket",
        "2026-02-06",
        "../openai/responses-websocket-semantic-2026-08-21.json",
        "event_semantic",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_preset",
        source="crates/pooler-server/tests/gateway_preset.rs",
        test_name="the_gateway_preset_uses_semantic_responses_websocket_with_continuation",
    ),
    (
        "openai",
        "responses-compact",
        "SDK-6.40.0",
        "../openai/responses-compact-2026-08-21.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_preset",
        source="crates/pooler-server/tests/gateway_preset.rs",
        test_name="responses_compact_replays_the_documented_same_wire_shape",
    ),
    (
        "openai",
        "realtime-websocket",
        "SDK-6.40.0",
        "../openai/realtime-websocket-2026-08-22.json",
        "event_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_preset",
        source="crates/pooler-server/tests/gateway_preset.rs",
        test_name="the_gateway_preset_validates_openai_realtime_lifecycle",
    ),
    (
        "openai",
        "realtime-control",
        "SDK-6.40.0",
        "../openai/realtime-control-2026-08-22.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="openai_realtime_control_routes_match_the_sdk_wire_contract",
    ),
    (
        "openai",
        "native-image-audio",
        "SDK-6.40.0",
        "../openai/native-image-audio-2026-08-22.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="openai_routes_satisfy_a_strict_openai_endpoint",
    ),
    (
        "openai",
        "native-video",
        "SDK-6.40.0",
        "../openai/native-video-2026-08-22.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="openai_video_routes_match_sdk_6_40_wire_contract_without_server_poll_state",
    ),
    (
        "kimi",
        "openai-compatible-chat",
        "open-platform-2026-08-22",
        "../kimi/gateway-native-2026-08-22.json",
        "json_structural",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="kimi_open_platform_is_mounted_with_its_native_contract",
    ),
    (
        "vertex",
        "publisher-model-actions",
        "v1-2026-08-22",
        "../vertex/gateway-native-2026-08-22.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="vertex_model_actions_use_project_paths_and_google_access_tokens",
    ),
    (
        "compatible",
        "explicit-openai-compatible",
        "config-v1-2026-08-22",
        "../compatible/nonstandard-openai-2026-08-22.json",
        "json_structural",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="explicit_compatible_provider_honors_nonstandard_paths_auth_and_models",
    ),
    (
        "antigravity",
        "pinned-internal",
        "2e6b1d83-2026-08-22",
        "../antigravity/gateway-native-2026-08-22.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="antigravity_internal_surface_is_explicitly_mounted_same_wire",
    ),
    (
        "gemini",
        "models-actions-interactions",
        "2026-08-21",
        "../gemini/gateway-same-wire-2026-08-21.json",
        "http_same_wire",
        "sanitized_local_reference",
    ): CargoTest(
        package="pooler-server",
        target="gateway_provider_auth",
        source="crates/pooler-server/tests/gateway_provider_auth.rs",
        test_name="gemini_routes_satisfy_a_strict_gemini_endpoint",
    ),
}


def parse_manifest_argument(arguments: list[str]) -> Path:
    if not arguments:
        return DEFAULT_MANIFEST
    if len(arguments) == 2 and arguments[0] == "--manifest":
        return Path(arguments[1]).resolve()
    raise SystemExit(
        "usage: scripts/verify-compatibility-fixtures.py "
        "[--manifest fixtures/compatibility/manifest.json]"
    )


def entry_key(entry: object, index: int) -> EntryKey:
    if not isinstance(entry, dict):
        raise ValueError(f"manifest entry {index} must be an object")
    values = []
    for field in ("adapter", "protocol", "version", "fixture", "equivalence", "status"):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"manifest entry {index} has an invalid {field}")
        values.append(value)
    return values[0], values[1], values[2], values[3], values[4], values[5]


def load_entries(manifest_path: Path) -> list[EntryKey]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not load manifest {manifest_path}: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("compatibility manifest must use schema_version 1")
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ValueError("compatibility manifest must contain at least one entry")

    entries: list[EntryKey] = []
    seen: set[EntryKey] = set()
    for index, raw_entry in enumerate(raw_entries):
        key = entry_key(raw_entry, index)
        if key in seen:
            raise ValueError(f"duplicate manifest entry: {describe(key)}")
        seen.add(key)
        entries.append(key)

    missing = sorted(seen - VERIFIERS.keys())
    stale = sorted(VERIFIERS.keys() - seen)
    if missing or stale:
        messages = []
        if missing:
            messages.append(
                "manifest rows without an executable verifier: "
                + ", ".join(describe(key) for key in missing)
            )
        if stale:
            messages.append(
                "verifiers without a manifest row: "
                + ", ".join(describe(key) for key in stale)
            )
        raise ValueError("; ".join(messages))
    return entries


def describe(key: EntryKey) -> str:
    adapter, protocol, version, fixture, equivalence, status = key
    return f"{adapter}/{protocol}/{version} ({fixture}; {equivalence}; {status})"


def resolve_fixture(manifest_path: Path, fixture: str) -> Path:
    path = (manifest_path.parent / fixture).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as error:
        raise ValueError(f"fixture escapes the repository: {fixture}") from error
    if not path.is_file():
        raise ValueError(f"fixture does not exist: {path}")
    return path


def assert_test_includes_fixture(verifier: CargoTest, fixture_path: Path) -> None:
    source_path = ROOT / verifier.source
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(
            f"could not read verifier source {source_path}: {error}"
        ) from error
    binding_pattern = re.compile(
        rf"#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*"
        rf"(?:async\s+)?fn\s+{re.escape(verifier.test_name)}\s*\([^)]*\)\s*"
        rf"\{{\s*const\s+MANIFEST_FIXTURE\s*:\s*&str\s*=\s*"
        rf"include_str!\(\s*\"([^\"]+)\"\s*\)\s*;"
    )
    binding = binding_pattern.search(source)
    if binding is None:
        raise ValueError(
            f"verifier source {source_path} must begin test {verifier.test_name} "
            "with a local MANIFEST_FIXTURE include_str! binding"
        )
    included_fixture = (source_path.parent / binding.group(1)).resolve()
    if fixture_path != included_fixture:
        test = verifier.target or verifier.test_name
        raise ValueError(
            f"verifier {verifier.package}/{test} does not include "
            f"the declared fixture {fixture_path.relative_to(ROOT)}"
        )


def command_for(verifier: Verifier, fixture_path: Path) -> list[str]:
    cargo = os.environ.get("CARGO", "cargo")
    if isinstance(verifier, CargoTest):
        command = [
            cargo,
            "test",
            "--locked",
            "-p",
            verifier.package,
            "--all-features",
        ]
        if verifier.target is not None:
            command.extend(["--test", verifier.target])
        command.append(verifier.test_name)
        return command
    return [
        cargo,
        "run",
        "--quiet",
        "--locked",
        "-p",
        "pooler-cli",
        "--",
        "--config",
        str(fixture_path),
        "check",
    ]


def main(arguments: list[str]) -> int:
    manifest_path = parse_manifest_argument(arguments)
    try:
        entries = load_entries(manifest_path)
        prepared = []
        for key in entries:
            fixture_path = resolve_fixture(manifest_path, key[3])
            verifier = VERIFIERS[key]
            if isinstance(verifier, CargoTest):
                assert_test_includes_fixture(verifier, fixture_path)
            prepared.append((key, verifier, fixture_path))
    except ValueError as error:
        print(f"compatibility fixture verification failed: {error}", file=sys.stderr)
        return 2

    failed = False
    for key, verifier, fixture_path in prepared:
        command = command_for(verifier, fixture_path)
        print(
            f"verifying {describe(key)}: "
            + " ".join(shlex.quote(argument) for argument in command),
            file=sys.stderr,
            flush=True,
        )
        output = ""
        try:
            result = subprocess.run(
                command,
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            output = result.stdout
            if output:
                print(output, file=sys.stderr, end="")
            return_code = result.returncode
        except OSError as error:
            print(f"could not run verifier: {error}", file=sys.stderr)
            return_code = 127
        plain_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
        test_ran = (
            not isinstance(verifier, CargoTest)
            or re.search(
                rf"^test (?:\S+::)*{re.escape(verifier.test_name)} \.\.\. ok$",
                plain_output,
                re.MULTILINE,
            )
            is not None
        )
        passed = return_code == 0 and test_ran
        failed = failed or not passed
        differences = []
        if return_code != 0:
            differences.append(f"verifier_exit_{return_code}")
        elif not test_ran:
            differences.append("verifier_test_not_run")
        print(
            json.dumps(
                {
                    "fixture": key[3],
                    "adapter": key[0],
                    "protocol": key[1],
                    "version": key[2],
                    "equivalence": key[4],
                    "evidence": key[5],
                    "status": "passed" if passed else "failed",
                    "equivalent": passed,
                    "differences": differences,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
