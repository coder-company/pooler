# Universal turnkey gateway

The `gateway` preset mounts the endpoint families a general OpenAI, Anthropic,
or Gemini client expects, without hand-authoring a route plan.

```yaml
imports:
  - preset: gateway
    as: gateway
    with:
      bind: 127.0.0.1:8400
      provider: openai
      secret: env:POOLER_GATEWAY_KEY

version: 1
```

```sh
POOLER_GATEWAY_KEY=... pooler serve --config config/gateway.example.yaml
```

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `bind` | `127.0.0.1:8400` | Listener address. |
| `provider` | `openai` | A provider this build ships an endpoint for. Run `pooler providers` for the list. |
| `upstream_url` | shipped provider base URL | Overrides the base URL for a private deployment or a test loopback. |
| `websocket_url` | `wss://api.openai.com` | `ws`/`wss` upstream for the Responses WebSocket route. Set this whenever `provider` is not `openai`; `provider` selects the REST base URL only, and a WebSocket route requires an explicit `ws`/`wss` transport. |
| `secret` | `env:POOLER_GATEWAY_KEY` | Secret reference for both upstreams. A reference only; never a literal. |

`as:` namespaces every listener, upstream, and route, so several gateways can
run in one process without colliding.

## What is mounted

| Route | Method and path | Mode |
| --- | --- | --- |
| `models` | `GET /v1/models` | opaque |
| `chat-completions` | `POST /v1/chat/completions` | patch |
| `completions` | `POST /v1/completions` | patch |
| `responses` | `POST /v1/responses` | patch |
| `responses-compact` | `POST /v1/responses/compact` | patch |
| `responses-websocket` | `GET /v1/responses` (upgrade) | opaque tunnel |
| `embeddings` | `POST /v1/embeddings` | patch |
| `messages` | `POST /v1/messages` | patch |
| `messages-count-tokens` | `POST /v1/messages/count_tokens` | patch |
| `images` | `/v1/images/*` | opaque |
| `audio` | `/v1/audio/*` | opaque |
| `files` | `/v1/files/*` | opaque |
| `batches` | `/v1/batches/*` | opaque |
| `gemini-models` | `GET /v1beta/models` | opaque |
| `gemini-model-actions` | `/v1beta/models/*` including `:generateContent`, `:streamGenerateContent`, and `:countTokens` | opaque |
| `gemini-interactions` | `/v1beta/interactions/*` | opaque |

## What the two modes claim

`patch` parses the caller's JSON, rewrites only the `/model` pointer to the
selected target's upstream model, and forwards everything else unchanged. This
is what makes catalog aliases, account pooling, capability filtering, and the
vendored request-facts dialect apply to a request. A model the catalog does not
know is rejected before any upstream call.

`opaque` forwards bytes or frames without semantic decoding. Media, file, and
batch surfaces keep provider-specific fields exactly, and upload bytes are
streamed once so the retry policy cannot replay them.

**Opaque forwarding is not provider-native semantic compatibility.** No route in
this preset translates between protocols. Routes that do that are configured
explicitly with a decoder and an encoder, and their compatibility claims live in
`fixtures/compatibility/MATRIX.md`.

Gemini carries the model and the action in the request path rather than in a
body field, so those routes forward opaquely instead of pretending a body
inspector can select a target.

## Where the model list comes from

The gateway upstream is declared with `known_provider`, so its base URL,
discovery parser, model aliases, and model exclusions come from the provider
catalog this build ships. Pooler then derives a catalog source for that upstream
automatically and discovers models at startup. That is what makes the preset
turnkey: the operator supplies a provider name and a secret reference, and the
patch routes select against the discovered catalog.

Because a `known_provider` upstream carries a native kind, the gateway needs a
real native runtime. `pooler serve` provides one. An embedder calling
`HttpProxyServer::bind` installs a disabled native runtime and startup discovery
will fail authorization before any transport; use
`HttpProxyServer::bind_with_native_runtime` instead.

## Limits

Every route declares explicit bounds. JSON routes cap the request body at
8 MiB; media, file, batch, and Gemini action routes cap it at 32 MiB. Streaming
routes additionally bound frame size, event size, queue bytes, and queue items.

## Evidence

- `crates/pooler-config/tests/gateway_preset.rs` covers expansion, alias
  isolation, parameter rejection, and secret redaction.
- `crates/pooler-server/tests/gateway_preset.rs` drives every mounted family
  through a real `HttpProxyServer` against a loopback upstream, including the
  WebSocket upgrade and caller-body preservation.
