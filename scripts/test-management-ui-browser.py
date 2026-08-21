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
        self.fail_all_reads = False
        self.slow_models = False
        self.reject_all = False
        self.models_started = threading.Event()
        self.reload_request_id = 1
        self.reload_status = "succeeded"
        self.posts: dict[str, int] = {}
        self.post_bodies: dict[str, bytes] = {}
        self.post_transfer_encoding: dict[str, str | None] = {}
        self.get_authorization: dict[str, str | None] = {}

STATE = MockState()


def payload(path: str) -> dict:
    generation = {"configuration_generation": 7}
    responses = {
        "/management/health": {**generation, "status": "ok", "management": {"mutations": True}, "credential_health_entries": 1, "cooling_provider_entries": 0},
        "/management/active": {"active": 1, "by_listener": {"main": 1}},
        "/management/health/providers": {**generation, "providers": [{"id": "openai", "transport": "http", "native": "openai", "auth_configured": True, "status": "not_cooling"}]},
        "/management/accounts": {**generation, "mutation_capable": True, "accounts": [{"id": "primary", "provider": "openai", "enabled": True, "selected": False, "auth_kind": "oauth", "available_actions": ["switch", "disable", "refresh", "revoke"], "status": "available", "failure_count": 0, "cooldown_until": None}]},
        "/management/quota": {**generation, "windows": [], "cooldowns": []},
        "/management/models": {**generation, "mutation_capable": True, "models": [{"id": "gpt-test", "selection_origin": "configured", "enabled": True, "targets": [{"provider": "openai", "upstream_model": "gpt-test", "capabilities": ["text"]}]}], "catalog_sources": [], "model_overrides": {}},
        "/management/catalog": {"catalog_generation": 2, "sources": []},
        "/management/listeners": {**generation, "listeners": [{"id": "main", "bind": "127.0.0.1:8080", "protocol": "http1", "tls": False, "route_count": 1}]},
        "/management/routes": {**generation, "routes": [{"id": "route", "listener": "main", "path": "/v1", "target": {"upstream": "openai"}}]},
        "/management/metrics": {**generation, "metrics": {"usage": [], "attempts": [], "latencies": []}},
        "/management/decisions": {"decisions": [{"id": "decision-1", "recorded_at": 1, "request_id": "request-123456", "route_id": "route", "model": "gpt-test", "selected_provider": "openai", "selected_credential": "primary", "attempt": 1, "reason": "selected", "candidates": [{"provider_id": "openai", "credential_id": "primary", "score": 10, "eligible": True, "reason": "healthy"}]}]},
        "/management/traces": {"traces": [], "dropped": 0},
        "/management/audit": {"events": []},
        "/management/reloads": {**generation, "reloads": [{"request_id": STATE.reload_request_id, "kind": "configuration", "status": STATE.reload_status, "requested_at_ms": 1, "completed_at_ms": 2, "accepted_configuration_generation": 7, "catalog_generation": 2}]},
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
        if source and source.is_file():
            mime = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
            self.send_bytes(200, source.read_bytes(), mime)
            return

        if not route.startswith("/management/"):
            self.send_bytes(404, b"not found", "text/plain")
            return
        STATE.get_authorization[route] = self.headers.get("Authorization")
        if STATE.reject_all or self.headers.get("Authorization") != "Bearer good-token":
            self.send_bytes(401, b'{"error":"unauthorized"}', "application/json")
            return
        if STATE.fail_all_reads:
            self.send_bytes(503, b'{"error":"management state unavailable"}', "application/json")
            return
        if route == "/management/health/providers" and STATE.fail_providers:
            self.send_bytes(503, b'{"error":"provider state unavailable"}', "application/json")
            return
        if STATE.slow_models and route in {"/management/models", "/management/catalog"}:
            STATE.models_started.set()
            time.sleep(0.45)
        body = json.dumps(payload(route), separators=(",", ":")).encode()
        self.send_bytes(200, body, "application/json")

    def do_POST(self) -> None:  # noqa: N802
        route = urlsplit(self.path).path
        if STATE.reject_all or self.headers.get("Authorization") != "Bearer good-token":
            self.send_bytes(401, b'{"error":"unauthorized"}', "application/json")
            return
        length = int(self.headers.get("Content-Length", "0"))
        STATE.post_bodies[route] = self.rfile.read(length) if length else b""
        STATE.post_transfer_encoding[route] = self.headers.get("Transfer-Encoding")
        STATE.posts[route] = STATE.posts.get(route, 0) + 1
        time.sleep(0.25)
        if route in {"/management/reload", "/management/models/reload"}:
            STATE.reload_request_id = 2
            STATE.reload_status = "succeeded"
            self.send_bytes(202, b'{"status":"pending","request_id":2}', "application/json")
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
    page = browser.new_page(viewport={"width": 1280, "height": 800}, accept_downloads=True)
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        response = page.goto(f"{origin}/management/ui/", wait_until="networkidle")
        expect(response is not None and response.headers.get("content-security-policy") == CSP, "strict CSP header missing")
        expect(page.locator("[style]").count() == 0, "inline style attribute rendered under strict CSP")
        expect(page.locator('[data-notice="auth"]').count() == 1, "parallel 401 responses were not coalesced")
        expect(page.locator("#session-dialog").evaluate("el => el.open"), "401 did not expose the session dialog")

        page.locator("#token-input").fill("wrong-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Token rejected").wait_for()
        expect(page.locator("#session-dialog").evaluate("el => el.open"), "invalid token did not return to the session dialog")
        expect(page.locator("#session-button", has_text="Connected").count() == 0, "unvalidated token was shown as connected")
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        expect(page.evaluate("localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''"), "bearer token was persisted in browser storage")
        expect(page.locator("#view").get_attribute("class") == "view view-overview", "overview view class missing")
        expect(page.locator('.nav-link[aria-current="page"]').get_attribute("data-route") == "overview", "current navigation state missing")
        expect(page.locator("table caption").count() > 0, "tables have no accessible captions")
        expect(page.locator("th:not([scope=col])").count() == 0, "column headers are missing scope")

        STATE.reject_all = True
        page.locator("#refresh-now").click()
        page.wait_for_selector("text=Authorization required")
        expect(page.locator("#view", has_text="openai").count() == 0, "stale management data remained rendered after a 401")
        STATE.reject_all = False
        page.locator("#token-input").fill("good-token")
        page.locator("#token-apply").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.wait_for_selector("text=openai")

        page.locator(".skip-link").focus()
        page.locator(".skip-link").press("Enter")
        page.wait_for_timeout(50)
        expect(page.evaluate("document.activeElement === document.querySelector('#main')"), "skip link did not move focus to main content")
        expect(page.locator("#theme-toggle").get_attribute("aria-label") in {"Switch to dark theme", "Switch to light theme"}, "theme control label is ambiguous")
        expect(page.locator("#session-dialog").get_attribute("aria-labelledby") == "session-title", "session dialog is unlabelled")

        for route in ("overview", "models", "accounts", "usage", "operations", "diagnostics"):
            page.locator(f'[data-route="{route}"]').click()
            page.wait_for_selector(f".view-{route}")
            expect(page.locator('.nav-link[aria-current="page"]').get_attribute("data-route") == route, f"{route} navigation state missing")
            expect(page.locator("[style]").count() == 0, f"{route} rendered an inline style under strict CSP")

        page.locator('[data-route="usage"]').click()
        page.wait_for_selector(".view-usage")
        STATE.fail_all_reads = True
        page.locator("#refresh-now").click()
        page.wait_for_selector(".endpoint-state")
        expect(page.locator(".endpoint-state").inner_text().startswith("Refresh failed."), "all-endpoint failure was labelled as partial")
        page.locator("#session-button", has_text="Not verified").wait_for()
        STATE.fail_all_reads = False
        page.locator("#refresh-now").click()
        page.locator("#session-button", has_text="Connected").wait_for()
        page.locator('[data-route="diagnostics"]').click()
        page.wait_for_selector(".view-diagnostics")

        page.locator(".skip-link").focus()
        page.locator(".skip-link").press("Enter")
        page.wait_for_timeout(50)
        expect(page.locator("#view").get_attribute("class") == "view view-diagnostics", "skip link changed the active route")

        page.locator('[data-route="models"]').click()
        page.wait_for_selector(".view-models .grid-stats-4")
        expect(page.locator("[style]").count() == 0, "model view introduced inline styles")
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        STATE.models_started.clear()
        STATE.slow_models = True
        page.locator('[data-route="models"]').click()
        expect(STATE.models_started.wait(timeout=2), "slow model request did not start")
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        page.wait_for_timeout(550)
        expect(page.locator("#view").get_attribute("class") == "view view-accounts", "stale model request overwrote account view")
        STATE.slow_models = False

        switch = page.locator('[data-account-action="switch"]')
        switch.click()
        expect("primary" in page.locator("#confirm-title").inner_text(), "switch confirmation does not name the selected account")
        expect(page.locator("#confirm-dialog").get_attribute("aria-describedby") == "confirm-copy", "confirmation dialog is unlabelled")
        page.locator("#confirm-cancel").focus()
        page.wait_for_timeout(10_300)
        expect(page.locator("#confirm-dialog").evaluate("el => el.open"), "polling closed the active confirmation dialog")
        expect(page.evaluate("document.activeElement === document.querySelector('#confirm-cancel')"), "polling displaced confirmation-dialog focus")
        page.locator("#confirm-cancel").click()

        disable = page.locator('[data-account-action="disable"]')
        disable.evaluate("el => { el.click(); el.click(); }")
        page.locator('[data-account-action="disable"]:not([aria-busy])').wait_for()
        expect(STATE.posts.get("/management/accounts/primary/disable") == 1, "double-submit reached the mutation endpoint")

        page.locator('[data-route="operations"]').click()
        page.wait_for_selector('[data-expand="decision-1"]')
        disclosure = page.locator('[data-expand="decision-1"]')
        expect(disclosure.get_attribute("aria-expanded") == "false", "disclosure initial state is wrong")
        disclosure.click()
        expect(page.locator('[data-expand="decision-1"]').get_attribute("aria-expanded") == "true", "disclosure state did not update")
        page.locator('[data-action="reload-config"]').click()
        page.locator("#confirm-accept").click()
        page.wait_for_selector(".banner-info")
        expect("Reload request 2 accepted" in page.locator(".banner-info").last.inner_text(), "accepted reload was not correlated in the UI")
        expect(STATE.posts.get("/management/reload") == 1, "configuration reload mutation was not sent exactly once")
        expect(STATE.post_bodies.get("/management/reload") == b"", "management mutation unexpectedly sent a body")
        expect(STATE.post_transfer_encoding.get("/management/reload") is None, "management mutation unexpectedly used Transfer-Encoding")
        page.wait_for_selector("text=succeeded")
        reload_history = page.locator(".section").filter(has_text="Reload history").first
        expect("2" in reload_history.inner_text() and "succeeded" in reload_history.inner_text(), "reload final outcome was not correlated to request 2")

        page.locator('[data-route="overview"]').click()
        page.wait_for_selector("text=openai")
        STATE.fail_providers = True
        page.locator("#refresh-now").click()
        page.wait_for_selector(".endpoint-state")
        expect(page.locator(".endpoint-state").inner_text().startswith("Partial refresh."), "partial endpoint state is not disclosed")
        expect(page.locator("text=openai").count() > 0, "stale provider data was discarded")
        expect("Partial" in page.locator("#footer-updated").inner_text(), "footer claims a complete refresh")
        STATE.fail_providers = False

        page.locator('[data-route="diagnostics"]').click()
        page.wait_for_selector(".view-diagnostics")
        with page.expect_download() as download_info:
            page.locator('[data-action="export"]').click()
        download_info.value.delete()
        expect(STATE.get_authorization.get("/management/export") == "Bearer good-token", "protected export did not use authenticated fetch")

        page.locator('[data-route="models"]').click()
        filter_input = page.locator("#model-filter")
        filter_input.fill("gpt")
        filter_input.evaluate("el => { el.dataset.qaIdentity = 'focused'; el.focus(); }")
        page.wait_for_timeout(10_300)
        expect(filter_input.evaluate("el => el.isConnected && el.dataset.qaIdentity === 'focused' && document.activeElement === el"), "polling replaced focused interactive DOM")

        page.set_viewport_size({"width": 390, "height": 780})
        page.locator('[data-route="accounts"]').click()
        page.wait_for_selector(".view-accounts")
        expect(page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "mobile layout overflows the viewport")
        expect(page.locator("#generation-badge").evaluate("el => getComputedStyle(el).display === 'none'"), "narrow header was not compacted")
        page.set_viewport_size({"width": 320, "height": 700})
        page.locator('[data-route="operations"]').click()
        page.wait_for_selector(".view-operations")
        expect(page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "320px operations layout overflows the viewport")
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
    parser.add_argument("--require-playwright", action="store_true", help="fail when Python Playwright or Chromium is unavailable")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        print(f"SKIP: Python Playwright is unavailable ({error}). See --help for installation.")
        return 1 if args.require_playwright else 0
    try:
        with sync_playwright() as playwright:
            run_browser(playwright)
    except Exception as error:
        message = str(error)
        if "Executable doesn't exist" in message or "playwright install" in message:
            print(f"SKIP: Playwright Chromium is unavailable ({error}). See --help for installation.")
            return 1 if args.require_playwright else 0
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
