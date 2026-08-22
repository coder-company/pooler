# CLIProxyAPI Plus versus Pooler

This comparison uses installed CLIProxyAPI Plus 7.2.125, commit `2e6b1d83`,
its redacted configuration shape, the upstream project at the same commit, and
Pooler's current implementation. It distinguishes practical product breadth
from the runtime guarantees each project is designed to provide.

## Why CLIProxyAPI Plus is more feature-rich today

CLIProxyAPI optimizes for immediate access to existing AI subscriptions. It
ships provider-specific login flows, model catalogs, aliases, quota behavior,
endpoint translations, and management tools as one ready-to-use gateway.
Pooler optimizes for a different foundation: independently composable routes,
explicit semantic-loss policy, byte-preserving proxy modes, bounded resources,
and retry/commit correctness across undocumented protocols.

The result is that Pooler has the stronger general protocol-runtime model, but
CLIProxyAPI currently has the broader integration product.

| Area | CLIProxyAPI Plus today | Pooler today | Practical gap |
| --- | --- | --- | --- |
| Provider breadth | OpenAI, Gemini, Claude, Codex, Grok/xAI, Kimi, Antigravity and compatibility providers | Native bindings for those families plus Cursor, Factory and Devin client adapters and catalog-driven compatible providers | Live credential-gated provider evidence |
| Login experience | Provider-specific Claude, Codex, Kimi, xAI and Antigravity login commands | Safe account lifecycle contracts and documented Codex OAuth; API-key guidance for other providers | Turnkey subscription login only where public provider contracts exist |
| Model catalog | Large merged catalog with aliases, exclusions, prefixes and virtual mappings | Vendored provider integrations, automatic discovery, model facts, aliases, exclusions and operator overrides | Ongoing evidence refresh and live-provider validation |
| Account operations | Ready-to-run multi-account rotation, quota switching and provider/project recovery | Ordered fallback, quota scopes, persisted atomic switching, account lifecycle controls and isolated OAuth refresh | Secret-gated real-account acceptance evidence |
| Protocol surface | Provider-native OpenAI Responses, Claude, Gemini Generate Content/Interactions, xAI WebSocket and media paths | Native Responses, Anthropic, Gemini, xAI realtime, media, files, batches and embeddings semantics | Remaining live-provider conformance evidence |
| Management | Remote management API, browser panel ecosystem, account/config/model controls, quota and usage tooling | Authenticated browser/API account and runtime-model controls, safe reload, quota/usage/cost views, traces, audit and redacted export | Remote TLS and durable browser-managed configuration editing |
| Extensions | Broad trusted plugin ABI for auth, models, scheduling, execution, translation, interception, CLI and management | Capability-limited external/WASM inspection and transformation | Plugin registry, provider plugin catalog and broader extension hooks |
| Operator UX | TUI, standalone modes and provider login switches | CLI/server workflow | Interactive operational tooling |
| Turnkey endpoint surface | One ready-to-use gateway mounts the expected endpoints by default | The [`gateway` preset](gateway.md) mounts nineteen provider-filtered routes across the OpenAI, Anthropic and Gemini surfaces from one import, with catalog-driven model selection and explicit bounds | Closed for mounted reachability; per-endpoint semantic translation remains route-by-route and evidence-gated |

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
| Pooler | 2.996 ms | 13.713 ms |
| CLIProxyAPI Plus | 94.369 ms | 117.054 ms |

This measures one OpenAI-compatible translation path, not total product
quality. CLIProxyAPI is substantially broader; Pooler is substantially lighter
on this common path.

## Recommended roadmap

Preserve Pooler's routing, loss, commitment, security and extension boundaries.
Do not move provider quirks into the core merely to increase feature count.
Build the missing integration layer in this order:

1. Keep the native Anthropic and Gemini adapters pinned to strict fixtures and add credential-gated live-provider conformance evidence.
2. Provider-specific OAuth/login modules mounted on the generic credential
   and refresh contracts.
3. A merged model-catalog service with aliases, exclusions, provenance and
   refresh policy.
4. Provider-aware quota/project recovery implemented as classifiers and policy
   plugins, not special cases in the proxy.
5. A secure management UI over the existing authenticated management API.
6. A signed extension registry and provider plugin catalog that retain the
   current process/WASM isolation boundary.
7. Promote the mounted semantic Responses WebSocket transport from strict-loopback evidence to credential-gated live OpenAI/xAI conformance; keep the native downstream WebSocket upgrade and Gemini Interactions same-wire until evidence supports stronger claims.

That path closes CLIProxyAPI's usability advantage without sacrificing the
properties that make Pooler a safer protocol runtime.
