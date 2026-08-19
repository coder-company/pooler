# Pooler Rust Architecture and Implementation Plan

## 1. Executive summary

Pooler will be a custom, composable protocol runtime for AI coding clients and model providers. It will expose any combination of HTTP, SSE, WebSocket, ConnectRPC, protobuf, and JSON API layouts while routing requests across local proxies, OAuth-backed subscriptions, native provider APIs, and custom upstreams.

Pooler will not force users to select one client personality, one adapter, one canonical public API, or one translation path. A deployment can mount individual routes and compose only the behavior each route needs. Devin, Cursor, Factory, Amp, OpenAI, Anthropic, and Gemini compatibility will be optional presets built from the same primitives rather than privileged runtime concepts.

Rust is selected because Pooler needs strict ownership of request and stream state, safe cancellation and retries, predictable memory use, robust concurrency, fuzzable parsers, a single deployable binary, and a future sandboxed extension boundary.

The first implementation will be a modular monolith using Tokio, Hyper, Axum, Tower, rustls, Serde, Prost, and SQLite. Configuration will compile into immutable execution plans. Mutable account, session, quota, and health state will remain separate from those plans.

## 2. Goals

Pooler must:

1. Serve multiple API layouts from one process and one or more listeners.
2. Allow unrelated routes from different layouts on the same listener.
3. Let each route choose opaque passthrough, structured patching, or semantic translation.
4. Route by listener, host, method, path, headers, model, account health, session, and policy.
5. Preserve original bytes whenever decoding is unnecessary.
6. Translate tools, reasoning, media, usage, errors, and events when protocols differ.
7. Support multiple providers, credentials, and accounts.
8. Classify failures before mutating account health.
9. Retry only when replay is safe and downstream output is uncommitted.
10. Propagate cancellation from the downstream client to upstream work.
11. Enforce bounded memory, body, frame, queue, and stream limits.
12. Support declarative overlays for routes, models, headers, body patches, policy, and listeners.
13. Support code-defined components for framing or semantics that configuration cannot express.
14. Explain every routing, retry, fallback, and cooldown decision.
15. Preserve opaque provider-specific fields when normalization would destroy state.
16. Build a sanitized record/replay compatibility corpus from real adapter behavior.

## 3. First-release non-goals

The first release will not:

- Implement a distributed control plane or hosted multi-tenant service.
- Load native dynamic libraries into the credential-bearing process.
- Run arbitrary user scripts inside the core runtime.
- Record raw prompts or responses by default.
- Promise lossless conversion between incompatible protocols.
- Retry transparently after visible downstream output unless a protocol has explicit resumability.
- Require OpenAI, Anthropic, or any other public layout as the primary API.
- Require every request to pass through a canonical semantic representation.
- Reproduce every CLIProxyAPI provider before replacing the adapters already in use.

## 4. Core architectural decisions

### 4.1 Composition instead of personality

The runtime unit is a compiled route plan, not a client personality. A route composes:

1. Listener and match rules.
2. Downstream authentication.
3. Body handling mode.
4. Inspection or decoding.
5. Request transforms.
6. Model and capability resolution.
7. Provider and credential selection.
8. Upstream encoding and transport.
9. Error classification and retry policy.
10. Response decoding or passthrough.
11. Response transforms.
12. Downstream encoding.

A named preset is configuration sugar that expands into these components. Runtime code never requires a global `client_type`, `personality`, or single adapter selection.

### 4.2 Four body modes

Every route chooses one mode:

- `opaque`: proxy bytes or frames without semantic decoding.
- `inspect`: extract routing fields while retaining the original body.
- `patch`: parse a known JSON or protobuf shape and apply bounded changes.
- `semantic`: decode into Pooler's protocol-neutral request and event types.

Opaque and inspect paths are first-class. Pooler will not decode and re-encode a Cursor-style pass-through request merely to fit an internal abstraction.

### 4.3 Explicit loss policy

Semantic routes select one policy:

- `reject`: fail before upstream execution if required semantics are unsupported.
- `preserve`: carry namespaced opaque extensions when the destination supports them.
- `degrade`: perform configured lossy conversion and emit a structured warning.

Silent loss of tools, images, reasoning signatures, IDs, or finish state is forbidden.

### 4.4 Immutable plans and isolated state

Configuration is validated and compiled into immutable route plans. Each request holds one configuration generation for its lifetime. Reload creates a new generation and atomically swaps it for new requests.

Mutable state is separate:

- Credential and model health.
- Quota recovery windows.
- Session affinity.
- OAuth refresh leases.
- In-flight request coalescing.
- Bounded cache entries.
- Metrics and decision records.

### 4.5 Modular monolith

Listeners, routing, adapters, policy, auth, and storage initially run in one process. This keeps cancellation, backpressure, streaming, and deployment straightforward. Services will split only when actual scaling or trust-boundary evidence justifies it.

## 5. Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│ Listeners: TCP, Unix socket, HTTP/1.1, HTTP/2, TLS           │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ Route table: host + method + path + headers + content type   │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│ Compiled plan: auth → inspect/decode → transform → select    │
└──────────────┬─────────────────────────────┬─────────────────┘
               │ opaque / inspect / patch    │ semantic
               ▼                             ▼
┌────────────────────────────┐  ┌──────────────────────────────┐
│ Original body and frames   │  │ Request and event model      │
│ plus extracted fields      │  │ plus opaque extensions       │
└──────────────┬─────────────┘  └──────────────┬───────────────┘
               └─────────────────┬──────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Policy: model, capability, session, health, quota, account   │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Transports: HTTP, SSE, WebSocket, ConnectRPC, protobuf       │
└──────────────────────────────────────────────────────────────┘
```

## 6. Rust workspace

```text
pooler/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── ARCHITECTURE_PLAN.md
├── config/pooler.example.yaml
├── crates/
│   ├── pooler-cli/
│   ├── pooler-server/
│   ├── pooler-core/
│   ├── pooler-config/
│   ├── pooler-http/
│   ├── pooler-protocol/
│   ├── pooler-policy/
│   ├── pooler-auth/
│   ├── pooler-store/
│   ├── pooler-observe/
│   ├── pooler-testkit/
│   ├── adapter-passthrough/
│   ├── adapter-openai/
│   ├── adapter-anthropic/
│   ├── adapter-factory/
│   └── adapter-devin/
├── proto/devin/
├── presets/
│   ├── cursor.yaml
│   ├── factory.yaml
│   └── devin.yaml
├── fixtures/
│   ├── cursor/
│   ├── factory/
│   └── devin/
└── tests/
    ├── conformance/
    ├── integration/
    └── failure-injection/
```

### Crate ownership

- `pooler-cli`: command parsing; `serve`, `check`, `routes`, `models`, `doctor`, `config render`, `fixture replay`, and `auth` commands.
- `pooler-server`: process lifecycle, listener startup, configuration reload, shutdown, and component wiring.
- `pooler-core`: identifiers, request context, plan contracts, capabilities, shared errors, extension storage, and registries.
- `pooler-config`: imports, presets, overlays, schema validation, source-aware errors, and plan compilation.
- `pooler-http`: Hyper/Axum/Tower integration, body limits, headers, TLS, SSE, WebSocket upgrades, and draining.
- `pooler-protocol`: optional semantic request and event types, opaque extensions, and conversion reports.
- `pooler-policy`: model resolution, target selection, retries, health, quotas, affinity, and explanations.
- `pooler-auth`: credentials, secret handles, OAuth, refresh coordination, and secure persistence.
- `pooler-store`: storage traits, encrypted-file storage, and SQLite.
- `pooler-observe`: tracing, metrics, redaction, audit events, and sanitized capture.
- `pooler-testkit`: scripted upstreams, fake clocks, codecs, fixture normalization, and failure injection.
- Adapter crates: independent inspectors, decoders, encoders, classifiers, route handlers, or stream codecs. An adapter crate does not have to represent one whole client.

## 7. Component contracts

### 7.1 Stable component identifiers

Configuration refers to implementations by identifiers such as:

```text
inspect.openai.model
decode.openai.responses
decode.factory.language_model
decode.devin.chat
encode.openai.chat
encode.factory.events
encode.devin.connect
transform.json.set
transform.model_alias
transport.http
transport.websocket
classify.codex
classify.anthropic
```

Built-ins register at startup. Compilation fails if a component is missing or adjacent representations are incompatible.

### 7.2 Conceptual route plan

```rust
pub struct RoutePlan {
    pub id: RouteId,
    pub generation: ConfigGeneration,
    pub downstream_auth: Arc<dyn DownstreamAuthenticator>,
    pub ingress: IngressPlan,
    pub request_steps: Vec<Arc<dyn RequestStep>>,
    pub target_resolver: Arc<dyn TargetResolver>,
    pub attempt_policy: Arc<dyn AttemptPolicy>,
    pub executor: Arc<dyn UpstreamExecutor>,
    pub response_steps: Vec<Arc<dyn ResponseStep>>,
    pub egress: EgressPlan,
    pub limits: RouteLimits,
    pub observability: ObservabilityPolicy,
}
```

The implementation may specialize plans by body mode to avoid unnecessary dynamic dispatch.

### 7.3 Request context

Each request receives:

- Request and trace IDs.
- Configuration generation.
- Listener and route IDs.
- Start time and deadline.
- Downstream identity.
- Cancellation token.
- Extracted model and session keys.
- Decision-record builder.
- Redaction policy.
- Typed extension map.

It never contains raw credential values.

### 7.4 Representations

```rust
pub enum RequestBody {
    Opaque(OpaqueBody),
    Buffered(bytes::Bytes),
    Json(PreservedJson),
    Protobuf(DynamicProto),
    Semantic(SemanticRequest),
}
```

Routes requiring byte identity remain opaque. Generated Prost types are preferred for stable protobuf protocols. Dynamic descriptors are optional for custom runtime-loaded schemas.

### 7.5 Request and response steps

Every step declares:

- Accepted input representation.
- Produced representation.
- Whether it mutates data.
- Whether it requires buffering.
- Whether it preserves replay safety.
- Required and produced capabilities.
- Potential conversion losses.

Response steps can operate on opaque chunks, SSE records, WebSocket frames, Connect envelopes, buffered values, or semantic events.

## 8. Routes and custom API layouts

### 8.1 Match dimensions

Routes match listener, host, method, exact path, path template, path prefix, headers, content type, WebSocket upgrade, and Connect protocol version.

Precedence is deterministic:

1. Exact path.
2. Path template.
3. Prefix.
4. More constrained header match.
5. Explicit priority.
6. Configuration order.

`pooler check` rejects indistinguishable routes at equal precedence.

### 8.2 Custom route without a personality

```yaml
version: 1

listeners:
  local:
    bind: 127.0.0.1:8400

providers:
  codex-local:
    transport:
      kind: http
      base_url: http://127.0.0.1:8319
    auth:
      kind: bearer_secret
      secret: env:POOLER_CODEX_KEY

routes:
  - id: private-inference
    listen: local
    match:
      methods: [POST]
      path: /my/private/inference
      content_types: [application/json]
    ingress:
      mode: patch
      inspectors: [inspect.openai.model]
    request:
      steps:
        - use: transform.json.set
          with:
            pointer: /reasoning/effort
            value: high
    target:
      provider: codex-local
      upstream_path: /v1/responses
    response:
      mode: opaque
```

This route borrows one field inspector but mounts no OpenAI personality and performs no semantic response conversion.

### 8.3 Optional presets

```yaml
imports:
  - preset: cursor
    as: cursor-low
    with:
      bind: 127.0.0.1:8331
      reasoning_effort: low
  - preset: cursor
    as: cursor-high
    with:
      bind: 127.0.0.1:8333
      reasoning_effort: high
```

`pooler config render` prints the expanded routes. Diagnostics retain both final IDs and preset source locations.

## 9. Configuration and overlays

### 9.1 Resolution order

1. Built-in operational defaults.
2. Imported preset defaults.
3. Main configuration.
4. Imported overlays in declaration order.
5. Environment-backed scalar references.
6. CLI overrides restricted to operational fields.

Secrets remain references and are never expanded by render commands.

### 9.2 Merge rules

- Maps merge recursively.
- Scalars replace earlier values.
- Lists replace by default.
- Named routes, providers, models, and listeners merge by ID only when `merge: true` is explicit.
- `remove: true` deletes a named declaration.
- Type-changing merges fail validation.
- Every final value retains its source location.

### 9.3 Mixed-layout deployment example

```yaml
version: 1

listeners:
  shared:
    bind: 127.0.0.1:8400
  devin:
    bind: 127.0.0.1:18473
  cursor-high:
    bind: 127.0.0.1:8333

providers:
  cliproxy:
    transport:
      kind: http
      base_url: http://127.0.0.1:8319
      connect_timeout: 5s
      request_timeout: 30m
    auth:
      kind: bearer_secret
      secret: env:POOLER_CLIPROXY_KEY
    error_classifier: classify.openai_compatible
  foundry:
    transport:
      kind: http
      base_url: http://127.0.0.1:8318
      connect_timeout: 5s
      request_timeout: 30m
    auth:
      kind: bearer_secret
      secret: env:POOLER_FOUNDRY_KEY
    error_classifier: classify.anthropic_compatible

models:
  - id: gpt-5.6-sol
    targets:
      - provider: cliproxy
        upstream_model: gpt-5.6-sol
        capabilities: [text, tools, reasoning, streaming]
  - id: opus-latest
    targets:
      - provider: foundry
        upstream_model: opus-latest
        capabilities: [text, images, tools, reasoning, streaming]

policies:
  default:
    selection:
      strategy: health_weighted
      session_affinity: 30m
    retry:
      maximum_attempts: 3
      maximum_credentials: 3
      before_commit_only: true
      statuses: [408, 429, 500, 502, 503, 504]
    stream:
      bootstrap_events: 1
      bootstrap_bytes: 64KiB
      bootstrap_timeout: 20s

routes:
  - id: factory-language-model
    listen: shared
    match:
      methods: [POST]
      path: /v3/ai/language-model
      content_types: [application/json]
    ingress:
      mode: semantic
      decoder: decode.factory.language_model
    target:
      policy: default
      model_from:
        header: ai-language-model-id
        fallback: request.model
    upstream:
      encoder: encode.openai.chat
      path: /v1/chat/completions
    response:
      decoder: decode.openai.chat.events
      encoder: encode.factory.events
    loss_policy: degrade

  - id: devin-chat
    listen: devin
    match:
      methods: [POST]
      path: /exa.api_server_pb.ApiServerService/GetChatMessage
      content_types: [application/connect+proto]
    ingress:
      mode: semantic
      framing: decode.connect.envelope
      decoder: decode.devin.chat
    target:
      policy: default
      model_from: request.model
    upstream:
      encoder: encode.openai.chat
      path: /v1/chat/completions
    response:
      decoder: decode.openai.chat.events
      encoder: encode.devin.connect
    loss_policy: reject

  - id: cursor-high
    listen: cursor-high
    match:
      methods: [POST]
      path_prefix: /
      content_types: [application/json]
    ingress:
      mode: patch
      inspectors: [inspect.openai.model]
    request:
      steps:
        - use: transform.json.set_when_model_prefix
          with:
            prefix: gpt-5.6-
            pointer: /reasoning_effort
            value: high
    target:
      policy: default
      model_from: inspected.model
    upstream:
      path_from_downstream: true
    response:
      mode: opaque
```

Factory uses semantic conversion, Devin uses framing plus semantics, and Cursor patches and passes through. They coexist without one controlling adapter.

## 10. Optional semantic model

### 10.1 Request fields

The semantic request represents:

- Public model request and resolved target metadata.
- Ordered input items.
- System, developer, user, assistant, and tool roles without premature collapsing.
- Text, images, files, audio, and provider-defined parts.
- Tool definitions, choice, calls, results, dependencies, and stable IDs.
- Reasoning effort, blocks, summaries, encrypted content, and signatures.
- Sampling and output controls.
- Response formats and JSON schemas.
- Cache hints and continuation IDs.
- Session identifiers.
- Namespaced opaque extensions.

### 10.2 Stream events

Events include response start, metadata, text block lifecycle, reasoning block lifecycle, tool-call lifecycle, media, usage, refusal, warning, completion, and failure. Every event carries an ordering sequence and stable block ID.

### 10.3 Extensions

Examples:

```text
openai.responses.encrypted_content
anthropic.thinking.signature
gemini.thought_signature
devin.execution_id
factory.response_metadata
cursor.request_identity
```

An extension contains bytes, media type, and replay policy. Debug output exposes only namespace and byte length.

### 10.4 Conversion reports

Encoders report preserved capabilities, degraded fields, dropped optional fields, unsupported required fields, and compatibility rules applied. The route's loss policy decides whether execution continues.

## 11. Streaming and transport

### 11.1 Body handling

- Enforce listener and route limits before buffering.
- Stream opaque bodies directly when replay and inspection are disabled.
- Spool replayable large bodies to owner-only temporary files only when enabled.
- Enforce decompressed limits for compressed input.
- Remove temporary files on completion, cancellation, and startup recovery.

### 11.2 Stream state machine

```text
Created
  → Connecting
  → AwaitingHeaders
  → ValidatingHeaders
  → BootstrapBuffering
  → Committed
  → Completed
```

States before `Committed` can enter `RetryableFailure`. After commitment, the only valid terminal outcomes are completion, downstream disconnect, or terminal failure. Private type-state wrappers will prevent calling pre-commit retry code after commitment.

### 11.3 SSE requirements

The parser must handle CRLF and LF, chunk-split fields, multiple data lines, comments, UTF-8 policy, terminal sentinels, per-line limits, per-event limits, and EOF without valid completion. It will be fuzzed.

### 11.4 ConnectRPC requirements

The codec must handle the flags byte, big-endian length, partial headers, partial payloads, negotiated compression, frame limits, data envelopes, end-stream envelopes, protocol errors, deadlines, and cancellation.

### 11.5 WebSocket requirements

Pooler must preserve message boundaries, proxy raw frames in opaque mode, bound frame/reassembly sizes, forward ping/pong/close correctly, and cancel the opposite side when either connection closes.

### 11.6 Backpressure

Streaming stages use bounded channels. Slow downstream consumers backpressure upstream reads. If a provider deadline or buffer ceiling makes continuation unsafe, Pooler terminates with a structured error identifying the limiting stage.

## 12. Models, accounts, and sessions

### 12.1 Model registry

Each public model records upstream targets, provider IDs, upstream names, capabilities, context/output limits, supported codecs, credential eligibility, metadata source, and freshness.

### 12.2 Eligibility filters

Targets are filtered by model, capability, codec availability, credential status, model/provider cooldown, concurrency, route policy, session requirements, and loss policy.

### 12.3 Selection strategies

Initial strategies:

- Round-robin.
- Smooth weighted round-robin.
- Fill-first.
- Least in-flight.
- Health-weighted scoring.
- Explicit ordered fallback.

### 12.4 Session affinity

Affinity keys can derive from configured headers, semantic session IDs, Devin conversation/cascade/execution IDs, OpenAI previous-response IDs, Anthropic metadata, or a deterministic hash of selected fields.

Affinity stores provider, credential, upstream model, creation time, last use, and expiry. It does not store prompt content.

### 12.5 Explainability

Every selection record includes candidates, filter reasons, scores, affinity decisions, selected provider, credential pseudonym, model alias resolution, attempt number, and configuration generation.

## 13. Errors, retries, and cooldown

### 13.1 Error taxonomy

- Downstream authentication failure.
- Invalid downstream request.
- Unsupported conversion.
- Provider authentication failure.
- Credential quota exhausted.
- Model quota exhausted.
- Provider rate limit or overload.
- Provider unavailable.
- Network failure or timeout.
- Invalid upstream response.
- Incomplete upstream stream.
- Internal invariant failure.
- Downstream disconnect.

Each classification contains scope, retryability, safe replay stage, optional recovery time, normalized public response, and redacted evidence.

### 13.2 Classification boundary

Provider classifiers inspect status, headers, structured bodies, OAuth errors, stream errors, and provider reason codes. They return classifications but do not mutate health. Policy applies health changes.

### 13.3 Replay safety

A request is replayable only when its body is retained or reproducible, the operation is idempotent or protected by an idempotency key, no downstream output is committed, no non-repeatable side effect occurred, and session/tool semantics permit another attempt.

### 13.4 Cooldown scopes

Cooldown may target credential, credential/model, provider, provider/model, or route. Invalid-request errors never cool credentials unless a provider-specific rule proves credential causation.

### 13.5 Retry budgets

Policies limit total attempts, credentials, providers, elapsed time, recovery wait, bootstrap bytes, and bootstrap events. Delays are jittered, bounded, and cancellation-aware.

## 14. Authentication and secrets

### 14.1 Downstream authentication

Initial mechanisms are static bearer keys, Unix-socket trust, explicitly enabled loopback trust, and later mutual TLS.

### 14.2 Secret sources

- Environment variables.
- Owner-only files.
- OS keyring.
- Encrypted local credential store.

Literal secrets require a development-only switch and startup warning.

### 14.3 Credential handles

Components receive a short-lived authorization materialization for one outbound request, not direct secret-store access. Secret types disable useful `Debug` output and zero memory where practical.

### 14.4 OAuth

Provider modules implement PKCE or device flow, state validation, token exchange, refresh, revocation when available, and identity discovery. One refresh lease per credential prevents refresh stampedes.

### 14.5 Safety requirements

- Owner-only credential files.
- Startup rejection of insecure permissions.
- Secret redaction in logs, traces, panic reports, and diagnostics.
- Header logging by allowlist.
- Rendered configuration retains references, never values.
- Management APIs never expose access or refresh tokens.

## 15. Persistence

SQLite stores credential metadata, encrypted local credential payloads when selected, health, cooldown, quota windows, affinity, migration state, and optional aggregate usage. WAL mode is enabled. Migrations are embedded and transactional.

In-flight requests, short caches, refresh leases, stream buffers, and active plans remain in memory.

Encryption uses a mature audited AEAD implementation. The master key comes from the OS keyring or configured external secret. Pooler will not invent cryptography.

## 16. Observability and management

### 16.1 Logs and traces

Structured records include request/trace IDs, listener, route, model, provider, credential pseudonym, attempt, retry reason, time to headers, time to first event, completion class, and usage. Bodies are excluded by default.

OpenTelemetry spans cover match, authentication, decoding, transforms, selection, every attempt, stream bootstrap, encoding, and persistence.

### 16.2 Metrics

- Requests and active requests by route.
- Attempts by provider and result class.
- Header, first-event, and end-to-end latency.
- Stream completion and incomplete-stream counts.
- Retries and fallback.
- Credential cooldown and quota state.
- OAuth refresh outcomes.
- Buffered bytes and backpressure termination.
- Coalescing and cache hits.

### 16.3 Management API

Disabled unless configured. Read-only endpoints expose health, configuration generation, redacted routes, models, provider/credential health, active counts, and recent decision records. Mutations require separate authorization and explicit remote enablement.

### 16.4 Diagnostic CLI

`pooler doctor` checks route conflicts, port conflicts, secret permissions, provider connectivity without prompts, codec registration, model targets, SQLite integrity, certificates, and configuration sources.

## 17. Caching and coalescing

Caching and coalescing are opt-in route policies. Eligibility requires a replay-safe operation, identity-aware keys where needed, bounded entries, and provider policy compatibility.

Cache keys include configuration generation, route, target inputs, relevant headers, effective body, and policy version.

The first release will not coalesce live semantic streams. Cursor parity may coalesce only fully buffered responses. Streaming fan-out requires an explicit slow-subscriber and cancellation policy before implementation.

## 18. Extension strategy

### 18.1 Built-ins first

Initial adapters compile into the binary while contracts evolve.

### 18.2 External process bridge

A supervised Unix-socket adapter protocol can preserve rapid TypeScript prototyping without putting JavaScript inside the core process. It receives bounded requests and streams but no direct credential-store access.

### 18.3 WebAssembly later

After contracts stabilize, Wasmtime and the WebAssembly Component Model can support request inspectors, JSON transforms, semantic transforms, event transforms, classifiers, and model discovery. Filesystem, network, clocks, random data, and secrets are denied unless explicitly granted.

### 18.4 No native dynamic loading

Rust ABI dynamic libraries will not be supported. Their version and memory boundaries are unsuitable for a credential-bearing daemon.

## 19. Migration of existing adapters

### 19.1 Cursor

Preserve reasoning-level listeners, model listing, Foundry/CLIProxy model routing, reasoning patching, auth replacement, bounded 429 retry, safe coalescing, and short cache behavior.

Use inspect/patch mode rather than semantic mode. Extract the model, patch only matching models, resolve provider from registry, and preserve response bytes. Acceptance requires equivalent routing and byte-equivalent opaque responses.

### 19.2 Factory/effects

Preserve model routes, `/v3/ai/language-model`, OpenAI compatibility, prompt/tool conversion, and streamed metadata, reasoning, text, tools, usage, and finish events.

Use semantic mode because event layouts differ. Parse SSE incrementally, propagate cancellation, preserve images, explicitly reject or degrade files, and derive advertised capabilities from tested translation support.

### 19.3 Devin

Preserve user status, team settings, model config, chat, analytics acknowledgement, self endpoint, schema licenses/notices, ConnectRPC gzip/end-stream framing, history, tools, IDs, and bounded context trimming.

Generate Prost types from licensed schema sources. Implement incremental Connect parsing. Preserve execution, conversation, request, and cascade identifiers. Advertise only conformance-tested capabilities.

### 19.4 Amp and other layouts

Path aliases and header changes remain route bundles. Unique framing or semantics receive focused components rather than a monolithic new personality.

## 20. Testing

### 20.1 Unit tests

Cover route precedence, overlay merges, capability matching, aliases, classification, retries, cooldown, affinity, redaction, and stream states.

### 20.2 Golden fixtures

Each fixture stores sanitized downstream request, extracted fields, expected upstream request, scripted upstream chunks, expected downstream chunks, conversion report, and expected health mutation. Equivalence is marked byte-level, JSON-structural, protobuf-semantic, or event-semantic.

### 20.3 Differential tests

Run the same request against an existing adapter and Pooler using one scripted upstream, then compare upstream requests and downstream status, headers, frames, and events. Intentional corrections are recorded in fixture metadata.

### 20.4 Fuzz targets

- SSE parsing.
- Connect envelope parsing.
- Decompression limits.
- JSON inspection and patching.
- Path templates.
- Overlay compilation.
- Tool-call delta aggregation.
- Reasoning extension preservation.

### 20.5 Required properties

- Stable fields survive supported round trips.
- Unknown extensions survive supported paths.
- Compilation is deterministic.
- No retry occurs after commitment.
- Invalid requests do not cool credentials by default.
- Cancellation releases every permit and lease.

### 20.6 Failure injection

Test connection refusal, TLS failure, slow headers, 401 refresh, 429 recovery, partial SSE, invalid UTF-8, missing terminal events, fragmented WebSockets, truncated Connect envelopes, and disconnects before and after commitment.

CI runs tests, Rustfmt, Clippy with denied warnings, dependency/license auditing, selected Loom concurrency tests, and sanitizer/leak jobs where supported.

## 21. Security model

Downstream clients and upstream responses are untrusted. Configuration is trusted administrative input but validated. Extensions are untrusted unless granted capabilities. Credentials are high-sensitivity assets.

Controls:

- Loopback binding by default.
- Authentication required for remote binding.
- Strict body, header, frame, decompression, and queue limits.
- Correct hop-by-hop header removal.
- Redirect following disabled by default.
- Provider hosts fixed by validated configuration to prevent SSRF.
- Management auth separated from inference auth.
- Debug endpoints disabled by default.
- Constant-time static-key comparison.
- Dependency and license audits.
- No attempt to evade provider enforcement; provider terms and account risks documented.

## 22. Dependency plan

- `tokio`: runtime.
- `hyper`, `hyper-util`: HTTP server/client primitives.
- `axum`: management and simple route integration.
- `tower`, `tower-http`: middleware, limits, and tracing.
- `http`, `http-body`, `http-body-util`: HTTP and streaming body contracts.
- `bytes`, `tokio-util`, `futures`: buffers, cancellation, codecs, streams.
- `serde`, `serde_json`: structured data.
- A maintained YAML crate selected after audit: configuration.
- `prost`, `prost-build`: protobuf.
- `flate2`: bounded gzip where required.
- `rustls`, `tokio-rustls`: TLS.
- `tokio-tungstenite`: WebSocket transport if needed beyond Hyper upgrades.
- `rusqlite` or `sqlx` with SQLite: selected after a cancellation/migration prototype.
- `tracing`, `tracing-subscriber`, `opentelemetry`: observability.
- `secrecy`, `zeroize`: secret wrappers.
- `clap`: CLI.
- `arc-swap`: configuration generations.
- `thiserror`: library errors.
- `anyhow`: executable-boundary context only.
- `uuid`: request IDs.
- `wasmtime`: later extension host, excluded from the first minimal binary.

Provider adapters may not introduce alternative HTTP or TLS stacks without review.

## 23. Resource and performance budgets

- Opaque loopback proxy overhead below 2 ms p95 under moderate concurrency, excluding upstream time.
- Semantic translation below 5 ms p95 for a 1 MiB JSON request.
- Bounded memory per route according to configured body, frame, bootstrap, and channel limits.
- No retained tasks, permits, or credential leases after cancellation grace periods.
- Startup below one second without network discovery.
- Configuration reload below 250 ms for the expected local route set.

Correctness takes precedence over synthetic throughput. Optimization follows profiling.

## 24. Implementation phases

### Phase 0: engineering baseline

Deliver Cargo workspace, pinned stable Rust, formatting/lint/test/audit CI, shared identifiers/errors, architecture decisions, and source-aware configuration parsing.

Exit: clean Linux/macOS builds; `pooler check` accepts a minimal config; CI rejects formatting, lint, vulnerability, and license failures.

### Phase 1: opaque custom proxy

Deliver multiple listeners, deterministic routes, opaque streaming, downstream bearer auth, secret references, HTTP upstreams, cancellation, limits, timeouts, draining, and structured logs.

Exit: arbitrary custom routes work without presets; disconnect cancels upstream; mixed layouts share a listener; header and body-limit tests pass.

### Phase 2: patch and overlay engine

Deliver JSON inspection, model extraction, bounded pointer transforms, model registry, static provider selection, overlay rendering, and Cursor preset.

Exit: current Cursor model/reasoning routing works; unrelated JSON survives structurally; opaque responses remain byte-identical; route conflicts fail with source locations.

### Phase 3: semantic events and Factory

Deliver semantic requests/events, extensions, conversion reports, SSE parser/encoder, OpenAI Chat codecs, Factory decoder/encoder, and commitment state machine.

Exit: Factory fixtures pass; text/reasoning/tools/usage stream incrementally; unsupported required semantics fail before upstream; post-commit retry is impossible.

### Phase 4: Devin and ConnectRPC

Deliver Prost generation, Connect envelopes, Devin metadata handlers, Devin chat codecs, gzip/frame limits, and identifier preservation.

Exit: installed Devin client lists models and completes tool conversations; compressed/fragmented tests pass; client disconnect cancels inference.

### Phase 5: account pooling

Deliver credential registry, selection strategies, affinity, classifiers, retry budgets, cooldowns, quota recovery, SQLite, and decision records.

Exit: malformed requests do not cool accounts; quota failures fail over; affinity rebinds safely; decisions are explainable; enabled state survives restart.

### Phase 6: OAuth and native providers

Deliver OAuth contracts, PKCE/device flows, secure persistence, refresh leases, first native subscription provider, and provider-specific quota parsing.

Exit: login, refresh, concurrent refresh, revocation, and secret-redaction tests pass.

### Phase 7: management and compatibility laboratory

Deliver read-only management, health/models/decisions, opt-in sanitized capture, replay CLI, compatibility matrix, and fuzz corpus.

Exit: operators can diagnose target selection without secrets; every adapter has a versioned conformance corpus; releases publish compatibility results.

### Phase 8: extension boundary

Deliver stable component contract and either supervised external adapters or WASM components based on demonstrated need, with capabilities and resource limits.

Exit: an extension can inspect/transform without process memory or credential access; crashes and exhaustion do not crash Pooler.

## 25. First useful release

The first useful release is complete when one Pooler process replaces the current Cursor, Factory/effects, and Devin bridges while exposing at least one arbitrary custom route, with no global personality selection.

It must prove:

1. Multiple listeners and mixed API layouts.
2. Cursor patch/passthrough routing.
3. Factory semantic SSE conversion.
4. Devin protobuf and ConnectRPC compatibility.
5. Shared providers and secure secret handling.
6. Bounded bodies, frames, streams, and retries.
7. Downstream-to-upstream cancellation.
8. Explainable target selection.
9. Differential fixtures against existing adapters.
10. One reproducible Rust binary with diagnostics.

This release prioritizes replacing proven local adapters over immediately matching every provider in CLIProxyAPI. Native subscription providers and a broader protocol matrix follow only after custom composition and streaming invariants are proven.
