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

- Phases 0–8 and prompt workstreams 1–9 are implemented and covered by local
  executable tests. This includes bounded opaque and semantic transports, strict
  imports/overlays, current-client adapters, account pooling, native provider
  contracts, typed durable configuration, encrypted request/usage history, secure
  onboarding, brokered documented OAuth, migration, dashboard and management-API
  TUI. Compatibility tiers remain separate: declared or fixture-verified behavior
  is not promoted to current-client, direct live-provider, artifact, or released
  conformance.
- The turnkey `gateway` preset is provider-aware rather than protocol-blind.
  OpenAI mounts models, Chat and legacy Completions, Embeddings, strict Files and
  Batches actions, Responses and Compact, native image/audio/video lifecycles,
  semantic Responses-over-WebSocket transport, Realtime and explicit SIP actions.
  xAI mounts its documented OpenAI-shaped subset; Anthropic mounts models, messages
  and token counting; Gemini mounts alias-aware model actions and versioned
  Interactions lifecycles. Unsupported provider/family combinations fail
  compilation, dynamic resources use strict templates, and caller credentials are
  stripped before provider-correct authentication is applied.
- Typed configuration never rewrites operator YAML. Managed sidecars, backups and
  durable recovery markers are owner-private, descriptor-validated, atomically
  persisted and synchronized. Recovery state remains through asynchronous reload;
  startup and every reload class fail closed until successful publication or exact
  verified restoration durably completes the transaction.
- Historical exact-SHA release benchmark and stress evidence passed for
  `9313fa1b09510f087ec5bd1851cc2c7109fac7bb`: three opaque p95 overhead results
  below 2 ms, three semantic p95 results below 5 ms, and 875,400 requests over 900
  seconds with zero unexpected failures or resource leaks. The exact implementation
  commit `50f9e66` CLIProxyAPI Plus comparison measured Pooler matched p50 overhead
  12.05 times lower and p95 5.81 times lower. Neither historical run establishes
  release acceptance for a later commit.
- Exact-SHA CI, Hardening and Secret Scan passed for `9313fa1`; later commits must
  obtain their own hosted and benchmark evidence. Product workflows use explicit
  2-vCPU Blacksmith Ubuntu x64/ARM64 classes and retain only the minimum available
  `blacksmith-6vcpu-macos-15` class for required macOS coverage.
- First useful release acceptance remains pending. Direct live-provider conformance
  for every advertised native provider, current Linux x86_64/ARM64 and macOS
  x86_64/ARM64 artifacts, signatures, SBOMs and hosted provenance require external
  credentials, entitlements, macOS capacity, signing material and publication.
  Historical or brokered evidence does not satisfy those gates. See
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
