# CLIProxyAPI Plus versus Pooler

This comparison uses installed CLIProxyAPI Plus 7.2.125, commit `2e6b1d83`,
its redacted configuration shape, the upstream project at the same commit, and
Pooler's current implementation. It distinguishes practical product breadth
from the runtime guarantees each project is designed to provide.

## Different strengths and remaining evidence gap

CLIProxyAPI optimizes for immediate access to existing AI subscriptions and
ships many provider-specific login flows as one gateway. Pooler now combines a
provider-aware turnkey gateway with independently composable routes, explicit
semantic-loss policy, byte-preserving proxy modes, bounded resources, durable
typed management, and retry/commit correctness.

Pooler's declared and fixture-verified protocol surface is broader and its
measured common path is lighter. CLIProxyAPI still has stronger released,
credential-gated evidence for several subscription login integrations. Pooler
does not promote local fixtures or imported private profiles to live-provider
or released conformance.

| Area | CLIProxyAPI Plus today | Pooler today | Practical gap |
| --- | --- | --- | --- |
| Provider breadth | OpenAI, Gemini, Claude, Codex, Grok/xAI, Kimi, Antigravity and compatibility providers | Native bindings for those families plus Cursor, Factory and Devin client adapters and catalog-driven compatible providers | Live credential-gated provider evidence |
| Login experience | Provider-specific Claude, Codex, Kimi, xAI and Antigravity login commands | Safe account lifecycle contracts and documented Codex OAuth; API-key guidance for other providers | Turnkey subscription login only where public provider contracts exist |
| Model catalog | Large merged catalog with aliases, exclusions, prefixes and virtual mappings | Vendored provider integrations, automatic discovery, model facts, aliases, exclusions and operator overrides | Ongoing evidence refresh and live-provider validation |
| Account operations | Ready-to-run multi-account rotation, quota switching and provider/project recovery | Ordered fallback, quota scopes, persisted atomic switching, account lifecycle controls and isolated OAuth refresh | Secret-gated real-account acceptance evidence |
| Protocol surface | Provider-native OpenAI Responses/Realtime, Claude, Gemini Generate Content/Interactions, xAI WebSocket and media paths | Native Responses, bounded semantic OpenAI Realtime WebSocket and sideband path, same-wire client-secret/session/transcription-session and explicit SIP controls, Anthropic, Gemini, xAI realtime, media, files, batches and embeddings semantics | Remaining live-provider conformance evidence; no translation-session creation endpoint is claimed because SDK 6.40.0 exports no method/path |
| Management | Remote management API, browser panel ecosystem, account/config/model controls, quota and usage tooling | Authenticated browser/API typed configuration, account and runtime-model controls; durable generation-safe reload/rollback; quota, usage, cost, traces, audit and redacted export | Live remote deployment evidence remains separate |
| Extensions | Broad trusted plugin ABI for auth, models, scheduling, execution, translation, interception, CLI and management | Capability-limited external/WASM inspection and transformation | Signed public plugin registry remains a release concern, not a runtime gap |
| Operator UX | TUI, standalone modes and provider login switches | Non-destructive init, safe dashboard launch, preflight, migration, management-API TUI, typed account drafts and brokered documented Codex OAuth | Additional subscription login flows require authoritative public contracts |
| Turnkey endpoint surface | One ready-to-use gateway mounts expected endpoints by default | The [`gateway` preset](gateway.md) mounts 33 strict OpenAI routes, including legacy Completions, Embeddings, Files, Batches, Responses/Compact, semantic Responses transport, Realtime/SIP and media lifecycles; provider filtering separately mounts xAI, Anthropic and Gemini/Interactions surfaces | Mounted reachability is closed for documented families; Alpha Search and Realtime translation-session creation remain intentionally absent because installed authoritative SDK evidence exposes no executable endpoint contract |

Primary CLIProxyAPI evidence:

- [provider and account surface](https://github.com/router-for-me/CLIProxyAPI/blob/2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e/README.md#L116-L151)
- [model aliases, exclusions and compatibility configuration](https://github.com/router-for-me/CLIProxyAPI/blob/2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e/config.example.yaml#L292-L381)
- [provider mappings and virtual models](https://github.com/router-for-me/CLIProxyAPI/blob/2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e/config.example.yaml#L541-L600)
- [plugin ABI](https://github.com/router-for-me/CLIProxyAPI/blob/2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e/sdk/pluginabi/types.go#L6-L79)

## Where Pooler is stronger

1. **Composition without a global personality.** Matching, ingress mode,
   transforms, target selection, retry, and response encoding are independent
   route-plan decisions rather than one gateway-wide provider personality.
2. **Explicit semantic loss.** `reject`, `preserve`, and `degrade` make loss of
   tools, media, reasoning, identifiers, usage, or terminal state observable
   and configurable instead of implicit.
3. **Opaque and inspected forwarding.** Pooler can preserve original bytes
   while extracting only bounded routing metadata, which is valuable for
   undocumented or byte-sensitive clients.
4. **Commit-aware retries.** The runtime forbids retry after downstream
   commitment and couples waiting, streaming, drain and cancellation ownership.
5. **Stronger extension isolation.** Pooler's process/WASM boundary is designed
   to deny credential and process-memory access; CLIProxyAPI's broader native
   plugin ABI treats plugins as trusted in-process code.
6. **Protocol-neutral correctness contracts.** Reasoning, IDs, tool state,
   usage, extensions, stream lifecycle, cancellation and resource limits are
   modeled independently of one provider.
7. **Evidence discipline.** Versioned sanitized fixtures, executable replay,
   fault injection, compatibility claims, resource accounting and explicit
   release invariants are first-class repository artifacts.

## Measured common-path performance

The loopback comparison in
[`cliproxyapi-benchmark-evidence-2026-08-20.md`](cliproxyapi-benchmark-evidence-2026-08-20.md)
uses identical valid 1 MiB Chat Completions requests and responses at
concurrency eight.

| Matched overhead versus direct | p50 | p95 |
| --- | ---: | ---: |
| Pooler | 8.405 ms | 23.018 ms |
| CLIProxyAPI Plus | 101.260 ms | 133.843 ms |

This exact implementation-commit run measured Pooler's p50 matched overhead at
12.05 times lower and p95 at 5.81 times lower. It measures one loopback
OpenAI-compatible path, not every provider, endpoint, host, or released build.

## Remaining acceptance work

Preserve Pooler's routing, loss, commitment, security and extension boundaries.
The remaining gap is evidence and publication rather than another speculative
runtime layer:

1. Run credential-gated live conformance for every advertised native provider
   when accounts, entitlements and terms-bound access are available.
2. Promote strict-loopback Responses, Realtime, Interactions, media and account
   evidence only after those live runs pass; never infer provider support from
   route presence.
3. Produce and publish Linux x86_64/ARM64 and macOS x86_64/ARM64 artifacts with
   checksums, signatures, SBOMs and hosted provenance on the exact release SHA.
4. Keep Alpha Search and Realtime translation-session creation absent unless an
   authoritative method, path, authentication contract and schema become
   available.

These steps retain Pooler's stronger safety and performance boundaries while
closing the remaining released-evidence advantage.
