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
- Phase 1 — opaque custom proxy: implemented and locally verified; cross-platform
  CI evidence is pending the pushed commit.
- Phase 2 — patch and overlay engine: in progress. Bounded JSON inspection,
  transforms, model declarations, runtime patching, and local E2E coverage are
  implemented, including model-based provider selection and upstream-model
  rewriting. Strict imports and overlays, deterministic expanded rendering, and a
  namespaced Cursor preset have local conformance coverage. Evidence from a real
  Cursor client or a current sanitized Cursor fixture remains before compatibility
  can be claimed.
- Phase 3 — semantic events and Factory: in progress. The protocol-neutral model,
  loss-accounted OpenAI Chat codecs, bounded incremental SSE framing, and grounded
  Factory LanguageModel V3 request/event codecs are implemented. Runtime semantic
  dispatch streams fragmented events with bounded backpressure and pre-connect loss
  enforcement. Sanitized local-reference fixtures cover text, reasoning, tools, and
  usage. Evidence from a current real Factory client remains before compatibility can
  be claimed.
- Phase 4 — Devin and ConnectRPC: in progress. Pinned Prost generation, shared
  bounded Connect/gzip framing, Devin metadata/chat codecs, a namespaced preset,
  sanitized cross-language fixtures, and runtime streaming/cancellation coverage are
  implemented. The installed Devin client model-list path is evidenced locally; a
  current real-client tool conversation through Pooler remains before compatibility
  can be claimed.
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
- Phases 7–8: pending.
- First useful release acceptance: pending.

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
