#!/usr/bin/env python3
"""Compare direct, Pooler, and CLIProxyAPI OpenAI Chat request latency.

The benchmark is entirely loopback: it starts one deterministic upstream and
isolated Pooler/CLIProxyAPI processes, sends identical one-MiB requests, checks
the exact one-MiB response, and tears down everything it started.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


MIB = 1024 * 1024
MODEL = "pooler-benchmark-model"
CLIENT_KEY = "pooler-benchmark-client-key"
UPSTREAM_KEY = "pooler-benchmark-upstream-key"
ENDPOINTS = ("direct", "pooler", "cliproxyapi")
ORDERS = (
    ENDPOINTS,
    ("direct", "cliproxyapi", "pooler"),
    ("pooler", "direct", "cliproxyapi"),
    ("pooler", "cliproxyapi", "direct"),
    ("cliproxyapi", "direct", "pooler"),
    ("cliproxyapi", "pooler", "direct"),
)


def exact_json_bytes(value: dict[str, Any], content: str, size: int) -> bytes:
    """Replace the sole message content so compact JSON is exactly ``size`` bytes."""
    body = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    padding = size - len(body)
    if padding < 0:
        raise ValueError(f"JSON envelope is larger than requested size {size}")
    value["messages"][0]["content"] = content * padding
    body = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    if len(body) != size:
        raise AssertionError(f"generated {len(body)} bytes, expected {size}")
    return body


REQUEST_VALUE: dict[str, Any] = {
    "model": MODEL,
    "messages": [{"role": "user", "content": ""}],
    "stream": False,
}
REQUEST_BYTES = exact_json_bytes(REQUEST_VALUE, "x", MIB)

RESPONSE_VALUE: dict[str, Any] = {
    "id": "chatcmpl-pooler-benchmark",
    "object": "chat.completion",
    "created": 0,
    "model": MODEL,
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": ""},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}
# ``exact_json_bytes`` expects the OpenAI request's messages location. Build the
# response padding directly to keep both payload constructors obvious.
_response_empty = json.dumps(RESPONSE_VALUE, separators=(",", ":")).encode()
RESPONSE_VALUE["choices"][0]["message"]["content"] = "y" * (MIB - len(_response_empty))
RESPONSE_BYTES = json.dumps(RESPONSE_VALUE, separators=(",", ":")).encode()
assert len(RESPONSE_BYTES) == MIB


class Upstream(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, UpstreamHandler)
        self.lock = threading.Lock()
        self.total = 0
        self.invalid = 0
        self.body_lengths: Counter[int] = Counter()
        self.body_hashes: Counter[str] = Counter()


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length", "-1"))
        body = self.rfile.read(length) if length >= 0 else b""
        valid = self.path == "/v1/chat/completions"
        try:
            valid = valid and json.loads(body) == REQUEST_VALUE
        except (UnicodeDecodeError, json.JSONDecodeError):
            valid = False

        server: Upstream = self.server  # type: ignore[assignment]
        with server.lock:
            server.total += 1
            server.body_lengths[len(body)] += 1
            server.body_hashes[hashlib.sha256(body).hexdigest()] += 1
            if not valid:
                server.invalid += 1

        if not valid:
            payload = b'{"error":{"message":"invalid benchmark request"}}'
            self.send_response(400)
        else:
            payload = RESPONSE_BYTES
            self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
    if port == 8319:
        return reserve_port()
    return port


def wait_for_port(process: subprocess.Popen[bytes], port: int, label: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited during startup with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"{label} did not listen on 127.0.0.1:{port}")


def stop_process(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
    return {"pid": process.pid, "returncode": process.returncode}


def listener_snapshot(port: int) -> list[dict[str, Any]]:
    """Return stable kernel identities for listeners without invoking services."""
    listeners: list[dict[str, Any]] = []
    for family, source in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
        try:
            lines = Path(source).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            local = fields[1]
            if int(local.rsplit(":", 1)[1], 16) == port and fields[3] == "0A":
                listeners.append(
                    {"family": family, "local": local, "inode": fields[9]}
                )
    return sorted(listeners, key=lambda item: (item["family"], item["local"], item["inode"]))


def percentile(values: list[int], percent: int) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def summary(values: list[int]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 50) / 1_000_000, 3),
        "p95_ms": round(percentile(values, 95) / 1_000_000, 3),
        "max_ms": round(max(values) / 1_000_000, 3),
    }


def request_once(connection: http.client.HTTPConnection) -> int:
    started = time.perf_counter_ns()
    connection.request(
        "POST",
        "/v1/chat/completions",
        body=REQUEST_BYTES,
        headers={
            "authorization": f"Bearer {CLIENT_KEY}",
            "content-type": "application/json",
            "user-agent": "pooler-loopback-benchmark/1",
        },
    )
    response = connection.getresponse()
    body = response.read()
    elapsed = time.perf_counter_ns() - started
    if response.status != 200:
        raise RuntimeError(f"unexpected HTTP status {response.status}: {body[:200]!r}")
    if response.getheader("content-type") != "application/json":
        raise RuntimeError(f"unexpected content type {response.getheader('content-type')!r}")
    if body != RESPONSE_BYTES:
        raise RuntimeError(
            f"response mismatch: got {len(body)} bytes sha256={hashlib.sha256(body).hexdigest()}"
        )
    return elapsed


def run_samples(
    ports: dict[str, int], warmup: int, samples: int, concurrency: int
) -> list[dict[str, Any]]:
    start_barrier = threading.Barrier(concurrency)
    measured_barrier = threading.Barrier(concurrency)

    def worker(worker_id: int) -> list[dict[str, Any]]:
        connections = {
            name: http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            for name, port in ports.items()
        }
        results: list[dict[str, Any]] = []
        try:
            start_barrier.wait()
            for sample_id in range(worker_id, warmup, concurrency):
                for name in ORDERS[sample_id % len(ORDERS)]:
                    request_once(connections[name])
            measured_barrier.wait()
            for sample_id in range(worker_id, samples, concurrency):
                order = ORDERS[sample_id % len(ORDERS)]
                latencies = {name: request_once(connections[name]) for name in order}
                results.append(
                    {
                        "sample": sample_id,
                        "worker": worker_id,
                        "order": list(order),
                        "latency_ns": latencies,
                        "matched_overhead_ns": {
                            "pooler": latencies["pooler"] - latencies["direct"],
                            "cliproxyapi": latencies["cliproxyapi"] - latencies["direct"],
                        },
                    }
                )
        finally:
            for connection in connections.values():
                connection.close()
        return results

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        groups = list(executor.map(worker, range(concurrency)))
    return sorted((sample for group in groups for sample in group), key=lambda item: item["sample"])


def binary_identity(path: Path, version_args: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        [str(path), *version_args], check=False, capture_output=True, timeout=10
    )
    text = (completed.stdout + completed.stderr).decode(errors="replace")
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "version_first_line": text.splitlines()[0] if text.splitlines() else "",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pooler-bin", type=Path, default=Path("target/release/pooler"))
    parser.add_argument(
        "--cliproxy-bin",
        type=Path,
        default=Path("/home/chaitanya/.local/bin/cliproxyapi-plus"),
    )
    parser.add_argument("--samples", type=int, default=240)
    parser.add_argument("--warmup", type=int, default=24)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < args.concurrency or args.warmup < args.concurrency:
        parser.error("--samples and --warmup must each be at least --concurrency")
    if args.concurrency < 2:
        parser.error("--concurrency must be at least 2")
    for label in ("pooler_bin", "cliproxy_bin"):
        path = getattr(args, label)
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"--{label.replace('_', '-')} must name an executable file: {path}")
    return args


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    upstream_port, pooler_port, cliproxy_port = (reserve_port() for _ in range(3))
    if len({upstream_port, pooler_port, cliproxy_port}) != 3:
        raise RuntimeError("ephemeral port allocation collision; rerun benchmark")

    live_8319_before = listener_snapshot(8319)
    upstream = Upstream(("127.0.0.1", upstream_port))
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    processes: list[tuple[str, subprocess.Popen[bytes], Any]] = []
    stopped: dict[str, Any] = {}
    report_path = args.output_dir / "report.json"

    with tempfile.TemporaryDirectory(prefix="pooler-cliproxy-benchmark-") as temp_name:
        temp = Path(temp_name)
        os.chmod(temp, 0o700)
        auth_dir = temp / "cliproxy-auth"
        auth_dir.mkdir(mode=0o700)
        pooler_config = temp / "pooler.yaml"
        cliproxy_config = temp / "cliproxy.yaml"
        pooler_config.write_text(
            f"""version: 1
listeners:
  benchmark:
    bind: 127.0.0.1:{pooler_port}
upstreams:
  deterministic:
    url: http://127.0.0.1:{upstream_port}
routes:
  - id: openai-chat-benchmark
    listen: benchmark
    match:
      methods: [POST]
      path: /v1/chat/completions
      content_types: [application/json]
    ingress: {{mode: opaque}}
    target:
      provider: deterministic
      upstream_path: /v1/chat/completions
    response: {{mode: opaque}}
"""
        )
        cliproxy_config.write_text(
            f"""host: 127.0.0.1
port: {cliproxy_port}
tls:
  enable: false
auth-dir: {auth_dir}
api-keys:
  - {CLIENT_KEY}
openai-compatibility:
  - name: pooler-benchmark
    base-url: http://127.0.0.1:{upstream_port}/v1
    api-key-entries:
      - api-key: {UPSTREAM_KEY}
    models:
      - name: {MODEL}
        alias: {MODEL}
debug: false
logging-to-file: false
usage-statistics-enabled: false
request-retry: 0
"""
        )
        os.chmod(pooler_config, 0o600)
        os.chmod(cliproxy_config, 0o600)

        isolated_env = os.environ.copy()
        isolated_env.update(
            {
                "HOME": str(temp),
                "XDG_CONFIG_HOME": str(temp / "xdg-config"),
                "XDG_STATE_HOME": str(temp / "xdg-state"),
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "ALL_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "127.0.0.1,localhost,::1",
            }
        )

        try:
            for name, command, log_name in (
                (
                    "pooler",
                    [str(args.pooler_bin), "serve", "--config", str(pooler_config)],
                    "pooler.log",
                ),
                (
                    "cliproxyapi",
                    [
                        str(args.cliproxy_bin),
                        "-config",
                        str(cliproxy_config),
                        "-local-model",
                    ],
                    "cliproxyapi.log",
                ),
            ):
                log = (args.output_dir / log_name).open("wb")
                process = subprocess.Popen(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    env=isolated_env,
                    start_new_session=True,
                )
                processes.append((name, process, log))
            wait_for_port(processes[0][1], pooler_port, "Pooler")
            wait_for_port(processes[1][1], cliproxy_port, "CLIProxyAPI")

            started_at = time.time()
            raw_samples = run_samples(
                {
                    "direct": upstream_port,
                    "pooler": pooler_port,
                    "cliproxyapi": cliproxy_port,
                },
                args.warmup,
                args.samples,
                args.concurrency,
            )
            elapsed = time.time() - started_at
            expected_upstream_requests = (args.warmup + args.samples) * len(ENDPOINTS)
            with upstream.lock:
                upstream_stats = {
                    "total_requests": upstream.total,
                    "expected_requests": expected_upstream_requests,
                    "invalid_requests": upstream.invalid,
                    "body_lengths": {str(key): value for key, value in upstream.body_lengths.items()},
                    "body_hashes": dict(upstream.body_hashes),
                }
            if upstream_stats["total_requests"] != expected_upstream_requests:
                raise RuntimeError(
                    f"upstream saw {upstream_stats['total_requests']} requests, expected {expected_upstream_requests}"
                )
            if upstream_stats["invalid_requests"] != 0:
                raise RuntimeError(f"upstream rejected {upstream_stats['invalid_requests']} requests")

            latencies = {
                name: [sample["latency_ns"][name] for sample in raw_samples]
                for name in ENDPOINTS
            }
            overheads = {
                name: [sample["matched_overhead_ns"][name] for sample in raw_samples]
                for name in ("pooler", "cliproxyapi")
            }
            report = {
                "schema_version": 1,
                "invocation": [sys.executable, *sys.argv],
                "methodology": {
                    "network": "loopback only; external HTTP(S) proxies forced to closed 127.0.0.1:9",
                    "request": "identical OpenAI Chat Completions JSON sent to each endpoint",
                    "response": "deterministic upstream body; exact bytes verified for every response",
                    "timing": "client request start through complete response body read",
                    "matching": "signed proxy latency minus direct latency for the same sample ID",
                    "percentile": "nearest-rank on independently sorted values",
                    "order": "six endpoint permutations rotated by sample ID",
                },
                "parameters": {
                    "samples_per_endpoint": args.samples,
                    "warmup_per_endpoint": args.warmup,
                    "concurrency": args.concurrency,
                    "request_bytes": len(REQUEST_BYTES),
                    "request_sha256": hashlib.sha256(REQUEST_BYTES).hexdigest(),
                    "response_bytes": len(RESPONSE_BYTES),
                    "response_sha256": hashlib.sha256(RESPONSE_BYTES).hexdigest(),
                    "model": MODEL,
                },
                "binaries": {
                    "pooler": binary_identity(args.pooler_bin, ["--version"]),
                    "cliproxyapi": binary_identity(args.cliproxy_bin, ["-h"]),
                },
                "ports": {
                    "upstream": upstream_port,
                    "pooler": pooler_port,
                    "cliproxyapi": cliproxy_port,
                    "protected_existing_service": 8319,
                },
                "summary": {
                    "latency": {name: summary(values) for name, values in latencies.items()},
                    "matched_overhead_vs_direct": {
                        name: summary(values) for name, values in overheads.items()
                    },
                },
                "upstream": upstream_stats,
                "wall_seconds": round(elapsed, 3),
                "raw_samples": raw_samples,
            }
            report_path.write_text(json.dumps(report, indent=2) + "\n")
        finally:
            for name, process, log in reversed(processes):
                stopped[name] = stop_process(process)
                log.close()

    upstream.shutdown()
    upstream.server_close()
    upstream_thread.join(timeout=3)
    live_8319_after = listener_snapshot(8319)
    if report_path.exists():
        report = json.loads(report_path.read_text())
        report["cleanup"] = {
            "processes": stopped,
            "temporary_config_removed": not Path(temp_name).exists(),
            "protected_8319_before": live_8319_before,
            "protected_8319_after": live_8319_after,
            "protected_8319_unchanged": live_8319_before == live_8319_after,
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        if live_8319_before != live_8319_after:
            raise RuntimeError("protected port 8319 listener identity changed during benchmark")
        print(json.dumps(report["summary"], indent=2))
        print(f"evidence: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # Keep failures concise; service logs remain as artifacts.
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise
