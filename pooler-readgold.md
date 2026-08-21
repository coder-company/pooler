# Pooler Read-Gold

This document is the implementation index for Pooler. The normative product scope is
defined by [GOAL.md](GOAL.md), and the architecture, invariants, phases, and exit
criteria are defined by [ARCHITECTURE_PLAN.md](ARCHITECTURE_PLAN.md).

## Delivery contract

Pooler is delivered phase-by-phase. A phase is complete only when its stated exit
criteria are covered by executable tests and all repository quality gates pass.
Unsupported compatibility is reported explicitly; it is never inferred from a route
name or advertised without conformance evidence.

## Current status

- Phase 0 — engineering baseline: implemented; local formatting, Clippy, tests,
  config-check smoke test, and code review pass. Linux/macOS CI evidence is pending
  the pushed commit.
- Phase 1 — opaque custom proxy: implemented and locally verified across HTTP/1.1,
  explicit h2c/HTTP/2, inbound TLS/ALPN, and bounded raw WebSocket tunneling;
  cross-platform CI evidence is pending the pushed commit.
- Phase 2 — patch and overlay engine: in progress. Bounded JSON inspection,
  transforms, model declarations, runtime patching, and local E2E coverage are
  implemented, including model-based provider selection and upstream-model
  rewriting. Strict imports and overlays, deterministic expanded rendering, and a
  namespaced Cursor preset have local conformance coverage. A sanitized
  current-client fixture records an installed Cursor Agent CLI
  `2026.08.04-aaa8809` request through an isolated Pooler listener and
  deterministic loopback upstream; it proves only the exercised OpenAI-compatible
  request shape and configured reasoning transform. Live-provider authorization,
  broader client features, and cross-platform evidence remain separate gates.
- Phase 3 — semantic events and Factory: in progress. The protocol-neutral model,
  loss-accounted OpenAI Chat codecs, bounded incremental SSE framing, and grounded
  Factory LanguageModel V3 request/event codecs are implemented. Runtime semantic
  dispatch streams fragmented events with bounded backpressure and pre-connect loss
  enforcement. Sanitized local-reference fixtures cover text, reasoning, tools, and
  usage. A sanitized `fx/0.0.3` V4 fixture records a real client request and
  deterministic loopback response through Pooler, including explicit loss for an
  unsupported provider tool. Live-provider authorization and broader V4 feature
  coverage remain separate compatibility gates.
- Phase 4 — Devin and ConnectRPC: in progress. Pinned Prost generation, shared
  bounded Connect/gzip framing, Devin metadata/chat codecs, a namespaced preset,
  sanitized cross-language fixtures, and runtime streaming/cancellation coverage are
  implemented. Installed Devin CLI `3000.4.16` completed a native text, tool-call,
  command execution, tool-result, and final-response conversation through Pooler
  against a deterministic loopback upstream. The sanitized fixture and HTTP-runtime
  replay cover its exact `source=Tool` follow-up shape and deterministic final
  response, not the initial tool-call emission, OS execution, or client orchestration.
  Live-provider authorization remains a separate gate.
- Phase 5 — account pooling: implemented and locally verified. Strict immutable
  account/pool/policy plans drive deterministic selection, bounded pre-commit retry,
  scoped cooldown and quota recovery, affinity with safe rebind policy, redacted
  decisions, and owner-private transactional SQLite persistence. Local restart and
  live quota-failover tests cover the phase exit invariants.
- Phase 6 — OAuth and native providers: implemented and locally verified. PKCE and
  device OAuth flows, cancellation-safe refresh leases, atomic encrypted token
  persistence, CLI login/status/revoke, and a status-gated native Codex provider are
  wired through pre-commit refresh and quota failover. Live provider authorization
  and account evidence remain before native compatibility can be advertised.
- Phase 7 — management and compatibility laboratory: implemented and locally
  verified. Authenticated read-only management, atomic dependency-aware reload,
  bounded metrics/traces, owner-private sanitized capture, executable fixture replay,
  a truthful compatibility matrix, and eight cargo-fuzz targets are wired and tested.
- Phase 8 — hardening and release: implemented and locally verified on Linux x86_64.
  Locked audit/deny gates, deterministic schema and compatibility reports, real
  mixed-protocol stress/benchmarks, no-import WASM extensions, deep-test/fuzz
  workflows, reproducible archives, SBOMs, checksums, signing, and provenance jobs
  are wired. The hardened three-run benchmark and 15-minute stress rerun for
  implementation commit `47f68b2` passed every enforced invariant. Native
  cross-platform CI and signed release artifacts remain publication gates.
- Turnkey gateway preset: implemented and locally verified, and deliberately
  provider-aware rather than universal. The `gateway` preset mounts only the
  endpoint families the selected provider's shipped integration documents and
  whose wire surface it serves, so OpenAI and xAI receive models, chat
  completions, responses, responses compact and the responses WebSocket,
  Anthropic receives models, messages and message token counting, and Gemini
  receives its models and model-action surfaces. A route declaring an endpoint
  family the target provider does not document is refused during compilation.
  Legacy completions, embeddings, images, audio, files, batches and Gemini
  Interactions are not mounted because no shipped integration documents them.
  A preset supplies only the protected credential reference; the provider's
  documented authentication kind, header and value prefix are preserved, so
  Anthropic receives `x-api-key` and Gemini its documented Google key
  placement. Any route Pooler authenticates strips caller-supplied credential
  headers, so an opaque, inspect or patch route can no longer forward one.
  `GET /v1/models` is answered from Pooler's active model view rather than
  forwarded: aliases, exclusions, runtime enablement, capability requirements
  and credential health all apply, and provider, upstream, account, secret and
  endpoint detail never appear. Evidence is
  `crates/pooler-config/tests/gateway_preset.rs`, and the mounted
  `HttpProxyServer` coverage in `crates/pooler-server/tests/{gateway_preset,
  gateway_provider_auth, gateway_models}.rs`, where provider traffic is judged
  by strict OpenAI, Anthropic and Gemini fakes that refuse wrong paths,
  methods, credential placement, headers, queries, content types and body
  shapes. The Responses WebSocket route remains an opaque tunnel rather than a
  semantic implementation, the Gemini routes forward rather than resolve
  aliases, and live-provider conformance for the preset remains a separate
  gate.
- First useful release acceptance: pending; the authoritative checklist is
  [`docs/release-acceptance.md`](docs/release-acceptance.md).

## Verification gates

The authoritative local gate is:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

Release performance, stress, security, compatibility, artifact, signature, checksum,
and SBOM evidence will be linked here as those gates become executable.
