#!/usr/bin/env python3
"""Deterministic browser QA for the embedded management dashboard.

Run from the repository root:

    python3 scripts/test-management-ui-browser.py

The test starts a loopback mock management listener and uses Python Playwright.
If Playwright (or its Chromium browser) is not installed, the default is an
explicit SKIP with exit status 0 so local asset generation remains usable.
Install with ``python3 -m pip install playwright && playwright install chromium``.
CI can pass ``--require-playwright`` to turn a missing dependency into failure.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "crates" / "pooler-server" / "ui"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)


class MockState:
    def __init__(self) -> None:
        self.fail_providers = False
        self.fail_usage_export = False
        self.fail_all_reads = False
        self.slow_models = False
        self.reject_all = False
        self.reject_oauth_device = False
        self.reject_account_draft = False
        self.delay_account_draft_unauthorized = False
        self.account_draft_started = threading.Event()
        self.release_account_draft = threading.Event()
        self.models_started = threading.Event()
        self.reload_request_id = 1
        self.reload_status = "succeeded"
        self.reload_outcome = "succeeded"
        self.posts: dict[str, int] = {}
        self.post_bodies: dict[str, bytes] = {}
        self.post_transfer_encoding: dict[str, str | None] = {}
        self.mutation_headers: dict[str, dict[str, str | None]] = {}
        self.get_authorization: dict[str, str | None] = {}
        self.get_targets: list[str] = []


STATE = MockState()


def payload(path: str) -> dict:
    generation = {"configuration_generation": 7}
    responses = {
        "/management/setup/options": {
            **generation,
            "providers": [
                {
                    "id": "openai",
                    "name": "OpenAI",
                    "request_dialect": "openai",
                    "native_kind": "openai_compatible",
                    "capabilities": ["text", "streaming"],
                    "endpoint_families": ["chat_completions", "models"],
                    "credential_environment_variables": ["OPENAI_API_KEY"],
                    "authentication": [
                        {
                            "method": "api_key",
                            "support": "supported",
                            "note": "Use a protected reference.",
                        },
                        {
                            "method": "authorization_code_pkce",
                            "support": "supported",
                            "note": "Use browser OAuth with a bundled public profile.",
                        },
                        {
                            "method": "device_code",
                            "support": "supported",
                            "note": "Documented built-in device flow.",
                        },
                    ],
                    "discovery": {
                        "available": True,
                        "parser": "openai",
                        "path": "/v1/models",
                    },
                    "configured_upstreams": ["openai-upstream"],
                    "clients": [
                        "native",
                        "openai",
                        "codex",
                        "cursor",
                        "droid",
                        "factory",
                        "devin",
                    ],
                }
            ],
            "clients": [
                {
                    "id": "native",
                    "name": "Provider-native API",
                    "description": "Native",
                },
                {
                    "id": "openai",
                    "name": "OpenAI-compatible client",
                    "description": "OpenAI",
                },
                {"id": "codex", "name": "Codex", "description": "Codex"},
                {"id": "cursor", "name": "Cursor", "description": "Cursor"},
                {"id": "droid", "name": "Factory Droid", "description": "Droid"},
                {"id": "factory", "name": "Factory protocol", "description": "Factory"},
                {"id": "devin", "name": "Devin protocol", "description": "Devin"},
            ],
        },
        "/management/setup/config": {
            "schema_version": 1,
            "validated": True,
            "configuration": "version: 1\nupstreams:\n  openai:\n    known_provider: openai\naccounts:\n  primary:\n    secret: env:OPENAI_API_KEY\n",
        },
        "/management/setup/test": {
            **generation,
            "ready": True,
            "connection": "verified",
            "checks": [
                {
                    "id": "generated_configuration",
                    "status": "passed",
                    "detail": "Generated YAML passed.",
                },
                {
                    "id": "connectivity",
                    "status": "passed",
                    "detail": "Bounded discovery succeeded.",
                },
            ],
        },
        "/management/oauth/device/77": {
            "schema_version": 1,
            "request_id": 77,
            "account": "primary",
            "generation": 7,
            "status": "authorization_required",
            "verification_uri": "https://provider.example/device",
            "verification_uri_complete": "https://provider.example/device/complete",
            "user_code": "BROWSER-CODE",
            "expires_in_seconds": 600,
        },
        "/management/config": {
            **generation,
            "etag": "generation-7",
            "management": {"mutations": True, "typed_drafts": True},
        },
        "/management/health": {
            **generation,
            "status": "ok",
            "management": {"mutations": True},
            "credential_health_entries": 1,
            "cooling_provider_entries": 0,
        },
        "/management/active": {"active": 1, "by_listener": {"main": 1}},
        "/management/health/providers": {
            **generation,
            "providers": [
                {
                    "id": "openai",
                    "transport": "http",
                    "native": "openai",
                    "auth_configured": True,
                    "status": "not_cooling",
                }
            ],
        },
        "/management/accounts": {
            **generation,
            "mutation_capable": True,
            "accounts": [
                {
                    "id": "primary",
                    "provider": "openai-upstream",
                    "enabled": True,
                    "selected": False,
                    "auth_kind": "oauth",
                    "available_actions": [
                        "switch",
                        "disable",
                        "refresh",
                        "revoke",
                        "oauth_device",
                    ],
                    "status": "available",
                    "failure_count": 0,
                    "cooldown_until": None,
                },
                {
                    "id": "custom-codex",
                    "provider": "custom-codex-native",
                    "enabled": True,
                    "selected": True,
                    "auth_kind": "oauth",
                    "available_actions": ["oauth_device"],
                    "status": "available",
                    "failure_count": 0,
                    "cooldown_until": None,
                },
            ],
        },
        "/management/quota": {**generation, "windows": [], "cooldowns": []},
        "/management/models": {
            **generation,
            "mutation_capable": True,
            "models": [
                {
                    "id": "gpt-test",
                    "selection_origin": "configured",
                    "enabled": True,
                    "targets": [
                        {
                            "provider": "openai",
                            "upstream_model": "gpt-test",
                            "capabilities": ["text"],
                        }
                    ],
                }
            ],
            "catalog_sources": [],
            "model_overrides": {},
        },
        "/management/catalog": {"catalog_generation": 2, "sources": []},
        "/management/listeners": {
            **generation,
            "listeners": [
                {
                    "id": "main",
                    "bind": "127.0.0.1:8080",
                    "protocol": "http1",
                    "tls": False,
                    "route_count": 1,
                }
            ],
        },
        "/management/routes": {
            **generation,
            "routes": [
                {
                    "id": "route",
                    "listener": "main",
                    "path": "/v1",
                    "target": {"upstream": "openai"},
                }
            ],
        },
        "/management/metrics": {
            **generation,
            "metrics": {"usage": [], "attempts": [], "latencies": []},
        },
        "/management/usage/aggregate": {
            "schema_version": 1,
            "group_by": [
                "route",
                "provider",
                "upstream_model",
                "result_class",
                "cost_provenance",
                "price_book_version",
            ],
            "series": [
                {
                    "dimensions": {
                        "route": "route",
                        "provider": "openai",
                        "upstream_model": "gpt-test-2026",
                        "result_class": "success",
                        "cost_provenance": "provider_reported",
                        "price_book_version": "",
                    },
                    "totals": {
                        "records": 2,
                        "input_tokens": 11,
                        "output_tokens": 7,
                        "reasoning_tokens": 3,
                        "cache_tokens": 2,
                        "image_units": 1,
                        "audio_units": 0,
                        "video_units": 0,
                        "latency_ms": 60,
                        "ttft_ms": 24,
                        "ttft_records": 2,
                        "cost_in_usd_ticks": 42,
                    },
                }
            ],
            "max_series": 256,
            "dropped_series_records": 3,
        },
        "/management/decisions": {
            "decisions": [
                {
                    "id": "decision-1",
                    "recorded_at": 1,
                    "request_id": "request-123456",
                    "route_id": "route",
                    "model": "gpt-test",
                    "selected_provider": "openai",
                    "selected_credential": "primary",
                    "attempt": 1,
                    "reason": "selected",
                    "candidates": [
                        {
                            "provider_id": "openai",
                            "credential_id": "primary",
                            "score": 10,
                            "eligible": True,
                            "reason": "healthy",
                        }
                    ],
                }
            ]
        },
        "/management/requests": {
            "schema_version": 1,
            "requests": [
                {
                    "request_id": "pool-request-browser-1",
                    "started_at": 1,
                    "updated_at": 30,
                    "listener": "main",
                    "route": "route",
                    "public_model": "gpt-test",
                    "upstream_model": "gpt-test-2026",
                    "provider": "openai",
                    "account_pseudonym": "account-pseudo",
                    "attempts": 2,
                    "committed": True,
                    "ttft_ms": 12,
                    "latency_ms": 30,
                    "status": 200,
                    "error_class": "success",
                    "quota_effect": "provider_quota",
                    "cooldown_effect": "credential",
                    "semantic_losses": ["temperature"],
                    "configuration_generation": 7,
                    "catalog_generation": 2,
                    "last_event_id": 6,
                }
            ],
            "limit": 50,
            "next_cursor": 5,
            "retention": {
                "max_events": 4096,
                "max_events_per_request": 64,
                "ttl_ms": 604800000,
            },
        },
        "/management/requests/export": {
            "schema_version": 1,
            "requests": [],
            "limit": 4096,
            "next_cursor": None,
            "retention": {
                "max_events": 4096,
                "max_events_per_request": 64,
                "ttl_ms": 604800000,
            },
        },
        "/management/requests/pool-request-browser-1/timeline": {
            "schema_version": 1,
            "request_id": "pool-request-browser-1",
            "timeline": [
                {
                    "id": 1,
                    "request_id": "pool-request-browser-1",
                    "event_index": 0,
                    "kind": "admission",
                    "recorded_at": 1,
                    "listener": "main",
                    "route_id": "route",
                    "provider": None,
                    "attempt": None,
                    "status": None,
                    "error_class": None,
                    "retry_reason": None,
                    "quota_effect": None,
                    "cooldown_effect": None,
                    "latency_ms": None,
                },
                {
                    "id": 6,
                    "request_id": "pool-request-browser-1",
                    "event_index": 5,
                    "kind": "completion",
                    "recorded_at": 30,
                    "listener": "main",
                    "route_id": "route",
                    "provider": "openai",
                    "attempt": 2,
                    "status": 200,
                    "error_class": "success",
                    "retry_reason": None,
                    "quota_effect": "provider_quota",
                    "cooldown_effect": "credential",
                    "latency_ms": 30,
                },
            ],
        },
        "/management/traces": {"traces": [], "dropped": 0},
        "/management/audit": {"events": []},
        "/management/reloads": {
            **generation,
            "reloads": [
                {
                    "request_id": STATE.reload_request_id,
                    "kind": "catalog",
                    "status": STATE.reload_status,
                    "requested_at_ms": 1,
                    "completed_at_ms": 2,
                    "accepted_configuration_generation": 7,
                    "configuration_generation": 7,
                    "catalog_generation": 2,
                }
            ],
        },
    }
    return responses.get(path, generation)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        _ = (format, args)

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_GET(self) -> None:  # noqa: N802
        route = urlsplit(self.path).path
        STATE.get_targets.append(self.path)
        static = {
            "/": UI / "index.html",
            "/management/ui/": UI / "index.html",
            "/management/ui.css": UI / "app.css",
            "/management/ui.js": UI / "app.js",
            "/management/ui/icons.js": UI / "icons.js",
            "/management/ui/providers.js": UI / "providers.js",
        }
        if route.startswith("/management/ui/fonts/"):
            static[route] = UI / "fonts" / route.rsplit("/", 1)[-1]
        if route.startswith("/management/ui/assets/"):
            static[route] = UI / "assets" / route.rsplit("/", 1)[-1]
        source = static.get(route)
        if source:
            mime = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
            try:
                body = source.read_bytes()
            except OSError as error:
                self.send_bytes(500, str(error).encode(), "text/plain")
                return
            self.send_bytes(200, body, mime)
            return

        if not route.startswith("/management/"):
            self.send_bytes(404, b"not found", "text/plain")
            return
        STATE.get_authorization[route] = self.headers.get("Authorization")
        if STATE.reject_all or self.headers.get("Authorization") != "Bearer good-token":
            self.send_bytes(401, b'{"error":"unauthorized"}', "application/json")
            return
        if STATE.fail_all_reads:
            self.send_bytes(
                503, b'{"error":"management state unavailable"}', "application/json"
            )
            return
        if route == "/management/health/providers" and STATE.fail_providers:
            self.send_bytes(
                503, b'{"error":"provider state unavailable"}', "application/json"
            )
            return
        if route == "/management/usage/export" and STATE.fail_usage_export:
            self.send_bytes(
                503,
                b'{"error":"usage export <unsafe>"}',
                "application/json",
            )
            return
        if STATE.slow_models and route in {"/management/models", "/management/catalog"}:
            STATE.models_started.set()
            time.sleep(0.45)
        body = json.dumps(payload(route), separators=(",", ":")).encode()
        self.send_bytes(200, body, "application/json")

    def do_POST(self) -> None:  # noqa: N802
        self.handle_mutation("POST")

    def do_PATCH(self) -> None:  # noqa: N802
        self.handle_mutation("PATCH")

    def handle_mutation(self, method: str) -> None:
        route = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length) if length else b""
        if STATE.reject_all or self.headers.get("Authorization") != "Bearer good-token":
            self.send_bytes(401, b'{"error":"unauthorized"}', "application/json")
            return
        if route == "/management/accounts/primary/oauth-device" and STATE.reject_oauth_device:
            self.send_bytes(401, b'{"error":"oauth authorization required"}', "application/json")
            return
        if route == "/management/config/accounts/draft" and (
            STATE.reject_account_draft or STATE.delay_account_draft_unauthorized
        ):
            if STATE.delay_account_draft_unauthorized:
                STATE.account_draft_started.set()
                STATE.release_account_draft.wait(timeout=5)
            self.send_bytes(
                401,
                b'{"error":"account draft authorization required"}',
                "application/json",
            )
            return
        STATE.post_bodies[route] = request_body
        STATE.post_transfer_encoding[route] = self.headers.get("Transfer-Encoding")
        STATE.mutation_headers[route] = {
            "authorization": self.headers.get("Authorization"),
            "if_match": self.headers.get("If-Match"),
            "content_type": self.headers.get("Content-Type"),
            "method": method,
        }
        STATE.posts[route] = STATE.posts.get(route, 0) + 1
        time.sleep(0.05 if route.startswith("/management/config/") else 0.25)
        if route in {"/management/reload", "/management/models/reload"}:
            STATE.reload_request_id += 1
            STATE.reload_status = STATE.reload_outcome
            body = json.dumps(
                {"status": "pending", "request_id": STATE.reload_request_id}
            ).encode()
            self.send_bytes(202, body, "application/json")
        elif route == "/management/config/accounts/draft":
            self.send_bytes(
                201,
                b'{"draft_id":12,"base_generation":7,"etag":"account-draft","valid":true,"semantic_diff":[{"section":"accounts","id":"browser-account","change":"added"}],"confirmation_token":"confirm-account"}',
                "application/json",
            )
        elif route == "/management/accounts/primary/oauth-device":
            self.send_bytes(
                202,
                b'{"status":"queued","request_id":77,"generation":7,"account":"primary","action":"oauth-device"}',
                "application/json",
            )
        elif route == "/management/config/drafts":
            self.send_bytes(
                201,
                b'{"draft_id":11,"base_generation":7,"etag":"draft-a","status":"draft"}',
                "application/json",
            )
        elif route == "/management/config/drafts/11" and method == "PATCH":
            self.send_bytes(
                200,
                b'{"draft_id":11,"base_generation":7,"etag":"draft-b","status":"draft"}',
                "application/json",
            )
        elif route == "/management/config/drafts/11/validate":
            self.send_bytes(
                200,
                b'{"draft_id":11,"etag":"draft-b","valid":true,"semantic_diff":[{"section":"models","id":"browser-model","change":"added"}],"confirmation_token":"confirm-browser"}',
                "application/json",
            )
        elif route == "/management/config/drafts/11/commit":
            self.send_bytes(
                202,
                b'{"status":"pending","request_id":41,"base_generation":7}',
                "application/json",
            )
        elif route == "/management/config/rollback":
            self.send_bytes(
                202,
                b'{"status":"pending","request_id":42,"base_generation":7}',
                "application/json",
            )
        else:
            self.send_bytes(200, b'{"status":"accepted"}', "application/json")


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_browser(playwright) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(
        viewport={"width": 1280, "height": 800}, accept_downloads=True
    )
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        response = page.goto(f"{origin}/management/ui/", wait_until="networkidle")
        expect(
            response is not None
            and response.headers.get("content-security-policy") == CSP,
            "strict CSP header missing",
        )
        expect(
            page.locator("[style]").count() == 0,
            "inline style attribute rendered under strict CSP",
        )
        page.wait_for_selector('[data-notice="auth"]')
        expect(
            page.locator('[data-notice="auth"]').count() == 1,
            "parallel 401 responses were not coalesced",
        )
        expect(
            page.locator("#session-dialog").evaluate("el => el.open"),
            "401 did not expose the session dialog",
        )
        expect(
            "without the Bearer prefix" in page.locator("#session-copy").inner_text(),
            "management session copy did not explain that the input excludes the Bearer prefix",
        )
        expect(
            page.get_by_text("Management secret", exact=True).count() == 1,
            "management session input was still labelled as a bearer token",
        )

        page.locator("#token-input").fill("wrong-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Token rejected").wait_for()
        expect(
            page.locator("#session-dialog").evaluate("el => el.open"),
            "invalid token did not return to the session dialog",
        )
        expect(
            page.locator("#session-button", has_text="Connected").count() == 0,
            "unvalidated token was shown as connected",
        )
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        expect(
            page.evaluate(
                "localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''"
            ),
            "bearer token was persisted in browser storage",
        )
        expect(
            page.locator("#view").get_attribute("class") == "view view-overview",
            "overview view class missing",
        )
        expect(
            page.locator('.nav-link[aria-current="page"]').get_attribute("data-route")
            == "overview",
            "current navigation state missing",
        )
        expect(
            page.locator("table caption").count() > 0,
            "tables have no accessible captions",
        )
        expect(
            page.locator("th:not([scope=col])").count() == 0,
            "column headers are missing scope",
        )

        STATE.reject_all = True
        page.locator("#refresh-now").click()
        page.wait_for_selector("text=Authorization required")
        expect(
            page.locator("#view", has_text="openai").count() == 0,
            "stale management data remained rendered after a 401",
        )
        STATE.reject_all = False
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.wait_for_selector("text=openai")

        page.locator(".skip-link").focus()
        page.locator(".skip-link").press("Enter")
        page.wait_for_timeout(50)
        expect(
            page.evaluate("document.activeElement === document.querySelector('#main')"),
            "skip link did not move focus to main content",
        )
        expect(
            page.locator("#theme-toggle").get_attribute("aria-label")
            in {"Switch to dark theme", "Switch to light theme"},
            "theme control label is ambiguous",
        )
        expect(
            page.locator("#session-dialog").get_attribute("aria-labelledby")
            == "session-title",
            "session dialog is unlabelled",
        )

        page.locator('[data-route="setup"]').click()
        page.wait_for_selector(".view-setup .setup-progress")
        expect(
            not page.locator('.view-setup input[type="password"]').count(),
            "setup wizard accepts a credential value",
        )
        expect(
            page.locator("[style]").count() == 0,
            "setup wizard rendered an inline style",
        )
        page.locator('[data-setup-action="next"]').click()
        expect(
            page.locator('#setup-auth option[value="device_code"]').count() == 1,
            "documented device flow was not offered",
        )
        expect(
            "pooler.setup.yaml" not in page.locator(".view-setup").inner_text(),
            "account step references a sidecar before it can be generated",
        )
        page.locator("#setup-account").fill("primary")
        page.locator('[data-setup-action="next"]').click()
        expect(
            page.locator("#setup-model").input_value() == "gpt-test",
            "setup did not reuse active model facts",
        )
        page.locator('[data-setup-action="next"]').click()
        page.locator("#setup-client").select_option("openai")
        page.locator('[data-setup-action="next"]').click()
        page.wait_for_selector(".setup-config")
        setup_yaml = page.locator(".setup-config").inner_text()
        expect(
            "env:OPENAI_API_KEY" in setup_yaml,
            "generated setup omitted protected secret reference",
        )
        expect(
            "sk-" not in setup_yaml and "Bearer " not in setup_yaml,
            "generated setup exposed a credential value",
        )
        expect(
            STATE.get_authorization.get("/management/setup/config")
            == "Bearer good-token",
            "setup configuration did not use authenticated fetch",
        )
        expect(
            page.get_by_role("link", name="Finish setup").count() == 0,
            "setup could finish before connection evidence",
        )
        activation_text = page.locator(".view-setup").inner_text()
        expect(
            "pooler --config pooler.setup.yaml --credential-key-ref env:POOLER_STORE_KEY serve"
            in activation_text,
            "serve instructions omit the OAuth credential-store key",
        )
        expect(
            "Reopen or reconnect this dashboard" in activation_text,
            "setup does not explain that verification targets the newly running instance",
        )
        STATE.reload_outcome = "failed"
        page.locator('[data-setup-action="test"]').click()
        page.wait_for_selector("text=Setup is not verified yet")
        expect(
            not any(
                target.startswith("/management/setup/test?")
                for target in STATE.get_targets
            ),
            "failed catalog reload still called setup verification",
        )
        expect(
            page.get_by_role("link", name="Finish setup").count() == 0,
            "failed catalog reload allowed setup completion",
        )
        STATE.reload_outcome = "succeeded"
        page.locator('[data-setup-action="test"]').click()
        page.wait_for_selector("text=Connection evidence verified")
        expect(
            page.get_by_role("link", name="Finish setup").count() == 1,
            "verified setup has no finish action",
        )
        expect(
            STATE.posts.get("/management/models/reload") == 2,
            "setup verification did not isolate failed and successful catalog reloads",
        )
        expect(
            STATE.post_bodies.get("/management/models/reload") == b"",
            "setup connection test mutation sent a body",
        )
        expect(
            STATE.get_authorization.get("/management/setup/test")
            == "Bearer good-token",
            "setup connection test did not use authenticated fetch",
        )
        expect(
            any(
                "reload_request_id=3" in target
                for target in STATE.get_targets
                if target.startswith("/management/setup/test?")
            ),
            "setup verification was not correlated to its successful catalog reload",
        )
        expect(
            page.evaluate("localStorage.length === 0 && sessionStorage.length === 0"),
            "setup state was persisted in browser storage",
        )
        STATE.reject_all = True
        page.locator("#refresh-now").click()
        page.wait_for_selector("text=Authorization required")
        expect(
            page.locator(".setup-config").count() == 0,
            "generated setup remained visible after authentication rejection",
        )
        STATE.reject_all = False
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.locator('[data-setup-action="generate"]').click()
        page.wait_for_selector(".setup-config")

        page.locator('[data-route="configuration"]').click()
        page.wait_for_selector('.view-configuration [data-config-action="create"]')
        expect(
            not page.locator('.view-configuration input[type="password"]').count(),
            "configuration editor accepts credential values",
        )
        page.locator('[data-config-action="create"]').click()
        page.wait_for_selector("text=Draft 11")
        page.locator('[data-config-field="id"]').fill("browser-model")
        page.locator('[data-config-field="value"]').fill(
            json.dumps(
                {
                    "id": "browser-model",
                    "targets": [
                        {"provider": "openai-upstream", "upstream_model": "gpt-browser"}
                    ],
                }
            )
        )
        page.locator('[data-config-action="patch"]').click()
        page.wait_for_selector("text=Typed patch applied")
        page.locator('[data-config-action="validate"]').click()
        page.wait_for_selector("text=Draft compiled")
        expect(
            "models/browser-model" in page.locator(".view-configuration").inner_text(),
            "semantic diff is not accessible",
        )
        page.locator('[data-config-action="commit"]').click()
        page.wait_for_selector("text=Configuration reload request 41 accepted")
        patch_route = "/management/config/drafts/11"
        patch = json.loads(STATE.post_bodies[patch_route])
        expect(
            patch
            == {
                "op": "upsert",
                "section": "models",
                "id": "browser-model",
                "value": {
                    "id": "browser-model",
                    "targets": [
                        {"provider": "openai-upstream", "upstream_model": "gpt-browser"}
                    ],
                },
            },
            f"browser emitted an unrestricted or malformed patch: {patch!r}",
        )
        expect(
            STATE.mutation_headers[patch_route]["method"] == "PATCH",
            "typed patch did not use PATCH",
        )
        expect(
            STATE.mutation_headers[patch_route]["if_match"] == "draft-a",
            "typed patch omitted its ETag",
        )
        expect(
            STATE.mutation_headers["/management/config/drafts/11/validate"]["if_match"]
            == "draft-b",
            "validation omitted its ETag",
        )
        expect(
            STATE.mutation_headers["/management/config/drafts/11/commit"]["if_match"]
            == "draft-b",
            "commit omitted its ETag",
        )
        expect(
            b"confirm-browser"
            in STATE.post_bodies["/management/config/drafts/11/commit"],
            "commit omitted explicit confirmation",
        )
        rollback_route = "/management/config/rollback"
        page.locator('[data-config-action="rollback"]').click()
        page.wait_for_selector("text=Rollback managed configuration?")
        expect(
            page.locator("#confirm-dialog").get_attribute("aria-describedby")
            == "confirm-copy",
            "rollback confirmation dialog is unlabelled",
        )
        page.locator("#confirm-cancel").click()
        expect(
            STATE.posts.get(rollback_route, 0) == 0,
            "cancelled rollback reached the mutation endpoint",
        )
        page.locator('[data-config-action="rollback"]').click()
        page.locator("#confirm-accept").click()
        page.wait_for_selector("text=Rollback reload request 42 accepted")
        expect(
            json.loads(STATE.post_bodies[rollback_route]) == {"confirm": "rollback"},
            "rollback omitted explicit confirmation",
        )
        expect(
            STATE.mutation_headers[rollback_route]["if_match"] == "generation-7",
            "rollback omitted its generation ETag",
        )

        expect(
            page.evaluate("localStorage.length === 0 && sessionStorage.length === 0"),
            "configuration draft was persisted in browser storage",
        )

        for route in (
            "setup",
            "configuration",
            "overview",
            "models",
            "accounts",
            "usage",
            "requests",
            "operations",
            "diagnostics",
        ):
            page.locator(f'[data-route="{route}"]').click()
            page.wait_for_selector(f".view-{route}")
            expect(
                page.locator('.nav-link[aria-current="page"]').get_attribute(
                    "data-route"
                )
                == route,
                f"{route} navigation state missing",
            )
            expect(
                page.locator("[style]").count() == 0,
                f"{route} rendered an inline style under strict CSP",
            )

        page.locator('[data-route="usage"]').click()
        page.wait_for_selector("text=Historical usage ledger")
        usage_text = page.locator(".view-usage").inner_text()
        expect(
            "provider_reported" in usage_text
            and "gpt-test-2026" in usage_text
            and "11 / 7" in usage_text
            and "Partial totals" in usage_text,
            "usage ledger omitted retained dimensions or token totals",
        )
        page.locator("#usage-range").select_option("7d")
        page.wait_for_timeout(100)
        expect(
            any(
                target.startswith("/management/usage/aggregate?")
                and "since=" in target
                and "until=" in target
                and "result_class" in target
                for target in STATE.get_targets
            ),
            "usage time-range selection did not issue a bounded query",
        )
        STATE.fail_usage_export = True
        page.locator("#usage-export").click()
        page.locator(".banner-error").last.wait_for()
        usage_export_error = page.locator(".banner-error").last
        expect(
            usage_export_error.inner_text()
            == "Usage export failed: usage export <unsafe>",
            "usage export failure was not rendered as plain text",
        )
        expect(
            usage_export_error.locator("img").count() == 0,
            "server-provided usage export error was interpreted as HTML",
        )
        expect(not errors, f"usage export failure caused a browser error: {errors}")
        expect(
            page.locator("#usage-export").is_enabled(),
            "usage export remained disabled after a failed request",
        )
        STATE.fail_usage_export = False

        page.locator('[data-route="requests"]').click()
        page.wait_for_selector('[data-request-id="pool-request-browser-1"]')
        request_text = page.locator(".view-requests").inner_text()
        expect(
            "pool-request-bro" in request_text and "account-pseudo" in request_text,
            "request explorer omitted bounded request metadata",
        )
        expect(
            "prompt" not in request_text.lower()
            and "authorization" not in request_text.lower()
            and "good-token" not in request_text,
            "request explorer rendered prohibited content",
        )
        page.locator('[data-request-filter="route"]').fill("route")
        page.locator('[data-request-filter="provider"]').fill("openai")
        page.locator('[data-request-filter="status"]').fill("200")
        page.locator('[data-request-action="apply"]').click()
        page.wait_for_timeout(100)
        expect(
            any(
                target.startswith("/management/requests?")
                and "route=route" in target
                and "provider=openai" in target
                and "status=200" in target
                for target in STATE.get_targets
            ),
            "request filters were not sent to the management API",
        )
        page.locator('[data-request-id="pool-request-browser-1"]').click()
        page.wait_for_selector("text=Timeline pool-request-browser-1")
        expect(
            "/management/requests/pool-request-browser-1/timeline" in STATE.get_targets,
            "request timeline was not loaded by logical request ID",
        )
        timeline_text = page.locator(".view-requests").inner_text()
        expect(
            "admission" in timeline_text
            and "completion" in timeline_text
            and "provider_quota" in timeline_text,
            "request timeline omitted lifecycle phases or bounded effects",
        )
        page.locator('[data-request-action="more"]').click()
        page.wait_for_timeout(100)
        expect(
            any("cursor=5" in target for target in STATE.get_targets),
            "request pagination did not use the server cursor",
        )
        with page.expect_download() as request_export:
            page.locator('[data-request-action="export"]').click()
        expect(
            request_export.value.suggested_filename.startswith(
                "pooler-request-history-"
            )
            and any(
                target.startswith("/management/requests/export?")
                and "limit=4096" in target
                for target in STATE.get_targets
            ),
            "request export did not use the bounded redacted export path",
        )

        page.locator('[data-route="usage"]').click()
        page.wait_for_selector(".view-usage")
        STATE.fail_all_reads = True
        page.locator("#refresh-now").click()
        page.wait_for_selector(".endpoint-state")
        expect(
            page.locator(".endpoint-state").inner_text().startswith("Refresh failed."),
            "all-endpoint failure was labelled as partial",
        )
        page.locator("#session-button", has_text="Not verified").wait_for()
        STATE.fail_all_reads = False
        page.locator("#refresh-now").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.locator('[data-route="diagnostics"]').click()
        page.wait_for_selector(".view-diagnostics")

        page.locator(".skip-link").focus()
        page.locator(".skip-link").press("Enter")
        page.wait_for_timeout(50)
        expect(
            page.locator("#view").get_attribute("class") == "view view-diagnostics",
            "skip link changed the active route",
        )

        page.locator('[data-route="models"]').click()
        page.wait_for_selector(".view-models .grid-stats-4")
        expect(
            page.locator("[style]").count() == 0, "model view introduced inline styles"
        )
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        STATE.models_started.clear()
        STATE.slow_models = True
        page.locator('[data-route="models"]').click()
        expect(STATE.models_started.wait(timeout=2), "slow model request did not start")
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        page.wait_for_timeout(550)
        expect(
            page.locator("#view").get_attribute("class") == "view view-accounts",
            "stale model request overwrote account view",
        )
        STATE.slow_models = False

        page.locator('[data-account-draft-field="id"]').fill("browser-account")
        page.locator('[data-account-draft-field="envName"]').fill(
            "BROWSER_PROVIDER_KEY"
        )
        STATE.reject_account_draft = True
        page.locator('[data-account-draft-action="create"]').click()
        page.get_by_text("Authorization required", exact=True).wait_for()
        expect(
            page.locator("#session-dialog").evaluate("el => el.open"),
            "account draft 401 did not return to the management session dialog",
        )
        expect(
            page.locator('[data-account-draft-action="create"]').count() == 0,
            "account draft 401 was overwritten by the accounts renderer",
        )
        STATE.reject_account_draft = False
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.wait_for_selector(".view-accounts")
        page.locator('[data-account-draft-field="id"]').fill("browser-account")
        page.locator('[data-account-draft-field="envName"]').fill(
            "BROWSER_PROVIDER_KEY"
        )
        page.locator('[data-account-draft-action="create"]').click()
        page.wait_for_selector(".view-configuration")
        account_draft_body = json.loads(
            STATE.post_bodies["/management/config/accounts/draft"]
        )
        expect(
            account_draft_body
            == {
                "id": "browser-account",
                "provider": "openai-upstream",
                "auth_kind": "api_key",
                "secret": {"kind": "env", "name": "BROWSER_PROVIDER_KEY"},
            },
            "typed account form did not send the bounded secret-reference shape",
        )
        expect(
            b"literal" not in STATE.post_bodies["/management/config/accounts/draft"],
            "typed account form accepted a literal credential",
        )
        page.get_by_text("Draft 12", exact=True).wait_for()
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        STATE.account_draft_started.clear()
        STATE.release_account_draft.clear()
        STATE.delay_account_draft_unauthorized = True
        page.locator('[data-account-draft-field="id"]').fill("stale-account")
        page.locator('[data-account-draft-field="envName"]').fill(
            "STALE_PROVIDER_KEY"
        )
        page.locator('[data-account-draft-action="create"]').click()
        expect(
            STATE.account_draft_started.wait(timeout=2),
            "delayed account draft mutation did not start",
        )
        page.locator("#session-button").click()
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        STATE.release_account_draft.set()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.wait_for_timeout(250)
        expect(
            page.get_by_text("Authorization required", exact=True).count() == 0,
            "a delayed 401 from an old account-draft session invalidated the new session",
        )
        STATE.delay_account_draft_unauthorized = False
        page.locator('[data-account-connect="primary"]').click()
        page.wait_for_selector(".connection-panel")
        connection_text = page.locator(".connection-panel").inner_text()
        expect(
            "auth login openai-upstream --profile openai --account primary --method oauth"
            in connection_text,
            "account connection guide did not separate the configured upstream from the account ID",
        )
        expect(
            not page.locator('.connection-panel input[type="password"]').count(),
            "account connection flow accepts credentials in the browser",
        )
        expect(
            "refresh token" in connection_text and "never receives" in connection_text,
            "account connection guide omits credential-boundary disclosure",
        )
        expect(
            "Brokered device OAuth" in connection_text,
            "documented device flow was not offered through the server-side broker",
        )
        STATE.reject_oauth_device = True
        page.locator('[data-account-oauth-device="primary"]').click()
        page.get_by_text("Authorization required", exact=True).wait_for()
        expect(
            page.locator("#session-dialog").evaluate("el => el.open"),
            "OAuth device start 401 did not return to the management session dialog",
        )
        expect(
            page.locator('[data-account-oauth-device="primary"]').count() == 0,
            "OAuth device start 401 was overwritten by the accounts renderer",
        )
        STATE.reject_oauth_device = False
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.wait_for_selector(".view-accounts")
        page.locator('[data-account-connect="primary"]').click()
        page.wait_for_selector(".connection-panel")
        page.locator('[data-account-oauth-device="primary"]').click()
        page.wait_for_timeout(3_000)
        expect(
            STATE.posts.get("/management/accounts/primary/oauth-device") == 1,
            "brokered device OAuth did not use the management mutation",
        )
        expect(
            STATE.post_bodies["/management/accounts/primary/oauth-device"] == b"",
            "brokered device OAuth sent a browser body",
        )
        expect(
            STATE.get_authorization.get("/management/oauth/device/77")
            == "Bearer good-token",
            "device OAuth status was not read with authenticated fetch",
        )
        expect(
            "BROWSER-CODE" in page.locator(".connection-panel").inner_text(),
            "device OAuth operator prompt was not rendered",
        )
        posts_before_status_check = dict(STATE.posts)
        page.locator("[data-account-connect-check]").click()
        page.wait_for_timeout(100)
        expect(
            STATE.posts == posts_before_status_check,
            "account status check sent a mutation",
        )
        expect(
            STATE.get_authorization.get("/management/accounts") == "Bearer good-token",
            "account status check did not use authenticated fetch",
        )
        page.locator("[data-account-connect-close]").click()
        expect(
            not page.locator(".connection-panel").count(),
            "account connection guide did not close",
        )
        page.locator('[data-account-connect="custom-codex"]').click()
        page.wait_for_selector(".connection-panel")
        expect(
            "Brokered device OAuth" in page.locator(".connection-panel").inner_text(),
            "custom Codex-native broker availability was not API-authoritative",
        )
        page.locator("[data-account-connect-close]").click()

        switch = page.locator('[data-account-action="switch"]')
        switch.click()
        expect(
            "primary" in page.locator("#confirm-title").inner_text(),
            "switch confirmation does not name the selected account",
        )
        expect(
            page.locator("#confirm-dialog").get_attribute("aria-describedby")
            == "confirm-copy",
            "confirmation dialog is unlabelled",
        )
        page.locator("#confirm-cancel").focus()
        page.wait_for_timeout(10_300)
        expect(
            page.locator("#confirm-dialog").evaluate("el => el.open"),
            "polling closed the active confirmation dialog",
        )
        expect(
            page.evaluate(
                "document.activeElement === document.querySelector('#confirm-cancel')"
            ),
            "polling displaced confirmation-dialog focus",
        )
        page.locator("#confirm-cancel").click()

        disable = page.locator('[data-account-action="disable"]')
        disable.evaluate("el => { el.click(); el.click(); }")
        page.locator('[data-account-action="disable"]:not([aria-busy])').wait_for()
        expect(
            STATE.posts.get("/management/accounts/primary/disable") == 1,
            "double-submit reached the mutation endpoint",
        )

        page.locator('[data-route="operations"]').click()
        page.wait_for_selector('[data-expand="decision-1"]')
        disclosure = page.locator('[data-expand="decision-1"]')
        expect(
            disclosure.get_attribute("aria-expanded") == "false",
            "disclosure initial state is wrong",
        )
        disclosure.click()
        expect(
            page.locator('[data-expand="decision-1"]').get_attribute("aria-expanded")
            == "true",
            "disclosure state did not update",
        )
        page.locator('[data-action="reload-config"]').click()
        page.locator("#confirm-accept").click()
        page.wait_for_selector(".banner-info")
        expect(
            "Reload request 4 accepted"
            in page.locator(".banner-info").last.inner_text(),
            "accepted reload was not correlated in the UI",
        )
        expect(
            STATE.posts.get("/management/reload") == 1,
            "configuration reload mutation was not sent exactly once",
        )
        expect(
            STATE.post_bodies.get("/management/reload") == b"",
            "management mutation unexpectedly sent a body",
        )
        expect(
            STATE.post_transfer_encoding.get("/management/reload") is None,
            "management mutation unexpectedly used Transfer-Encoding",
        )
        page.wait_for_function(
            """() => [...document.querySelectorAll('.section')].some((section) => section.textContent.includes('Reload history') && section.textContent.includes('4') && section.textContent.includes('succeeded'))"""
        )
        reload_history = (
            page.locator(".section").filter(has_text="Reload history").first
        )
        reload_history_text = reload_history.inner_text()
        expect(
            "4" in reload_history_text and "succeeded" in reload_history_text,
            f"reload final outcome was not correlated to request 4: {reload_history_text!r}",
        )

        page.locator('[data-route="overview"]').click()
        page.wait_for_selector("text=openai")
        STATE.fail_providers = True
        page.locator("#refresh-now").click()
        page.wait_for_selector(".endpoint-state")
        expect(
            page.locator(".endpoint-state").inner_text().startswith("Partial refresh."),
            "partial endpoint state is not disclosed",
        )
        expect(
            page.locator("text=openai").count() > 0, "stale provider data was discarded"
        )
        expect(
            "Partial" in page.locator("#footer-updated").inner_text(),
            "footer claims a complete refresh",
        )
        STATE.fail_providers = False

        page.locator('[data-route="diagnostics"]').click()
        page.wait_for_selector(".view-diagnostics")
        with page.expect_download() as download_info:
            page.locator('[data-action="export"]').click()
        download_info.value.delete()
        expect(
            STATE.get_authorization.get("/management/export") == "Bearer good-token",
            "protected export did not use authenticated fetch",
        )

        page.locator('[data-route="models"]').click()
        filter_input = page.locator("#model-filter")
        filter_input.fill("gpt")
        filter_input.evaluate(
            "el => { el.dataset.qaIdentity = 'focused'; el.focus(); }"
        )
        page.wait_for_timeout(10_300)
        expect(
            filter_input.evaluate(
                "el => el.isConnected && el.dataset.qaIdentity === 'focused' && document.activeElement === el"
            ),
            "polling replaced focused interactive DOM",
        )

        page.set_viewport_size({"width": 390, "height": 780})
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        expect(
            page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),
            "mobile layout overflows the viewport",
        )
        expect(
            page.locator("#generation-badge").evaluate(
                "el => getComputedStyle(el).display === 'none'"
            ),
            "narrow header was not compacted",
        )
        page.set_viewport_size({"width": 320, "height": 700})
        page.locator('[data-route="operations"]').click()
        page.wait_for_selector(".view-operations")
        expect(
            page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),
            "320px operations layout overflows the viewport",
        )
        page.locator('[data-route="setup"]').click()
        page.wait_for_selector(".view-setup")
        if page.locator(".view-setup .setup-config").count() == 0:
            page.locator('[data-setup-action="generate"]').click()
            page.wait_for_selector(".view-setup .setup-config")
        expect(
            page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),
            "320px setup layout overflows the viewport",
        )

        page.locator('[data-route="usage"]').click()
        page.wait_for_selector("#usage-export")
        STATE.reject_all = True
        page.locator("#usage-export").click()
        authorization_required = page.get_by_text("Authorization required", exact=True)
        authorization_required.wait_for()
        expect(
            authorization_required.count() == 1,
            "usage export authentication failure did not enter the authorization-required state",
        )
        STATE.reject_all = False
        expect(not errors, f"browser page errors: {errors}")
        print("PASS: management dashboard browser QA")
    finally:
        browser.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Local optional dependency:\n"
            "  python3 -m pip install playwright\n"
            "  playwright install chromium\n\n"
            "Use --require-playwright in CI so an unavailable browser fails instead of skipping."
        ),
    )
    parser.add_argument(
        "--require-playwright",
        action="store_true",
        help="fail when Python Playwright or Chromium is unavailable",
    )
    return parser.parse_args()


def missing_playwright_browser(message: str) -> bool:
    return any(
        marker in message
        for marker in ("Executable doesn't exist", "playwright install")
    )


def main() -> int:
    args = parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        print(
            f"SKIP: Python Playwright is unavailable ({error}). See --help for installation."
        )
        return 1 if args.require_playwright else 0
    try:
        with sync_playwright() as playwright:
            run_browser(playwright)
    except Exception as error:
        message = str(error)
        if missing_playwright_browser(message):
            print(
                f"SKIP: Playwright Chromium is unavailable ({error}). See --help for installation."
            )
            return 1 if args.require_playwright else 0
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
