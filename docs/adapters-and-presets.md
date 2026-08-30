# Adapters and presets

A preset is a built-in configuration fragment that mounts the listeners, routes, decoders, and transforms one client expects. Import a preset instead of hand-authoring a route plan.

Pooler ships seven presets: `cursor`, `devin`, `factory`, `fx`, `gateway`, `media`, and `xai`.

## Import a preset

```yaml
version: 2

imports:
  - preset: cursor
    as: cursor-adapter
    with:
      bind: 127.0.0.1:8333
```

The `as` value namespaces the generated listener, upstream, and route identifiers, so you can import the same preset twice with different parameters.

Every preset rejects unknown parameters. Use the exact parameter names in the table below, then validate with `pooler check`.

## Preset reference

| Preset | Client | Default bind | Accepted `with:` parameters |
| :--- | :--- | :--- | :--- |
| `cursor` | Cursor | `127.0.0.1:8333` | `bind`, `upstream_url`, `secret`, `reasoning_effort`, `model_prefix` |
| `devin` | Devin | `127.0.0.1:18473` | `bind`, `upstream_url`, `secret` |
| `factory` | Factory Droid | `127.0.0.1:18474` | `bind`, `upstream_url`, `secret` |
| `fx` | Vercel Labs fx | `127.0.0.1:18475` | `bind`, `upstream_url`, `secret` |
| `xai` | xAI Grok | `127.0.0.1:18476` | `bind`, `rest_url`, `websocket_url`, `secret` |
| `media` | Media surfaces | `127.0.0.1:18476` | `bind`, `upstream_url`, `secret` |
| `gateway` | OpenAI, Anthropic, and Gemini SDKs | `127.0.0.1:8400` | `bind`, `provider`, `upstream_url`, `websocket_url`, `secret` |

The `xai` preset takes `rest_url`, not `upstream_url`, because it declares separate REST and WebSocket transports. The `media` preset shares port `18476` with `xai`; change one `bind` if you import both.

---

## Client prerequisites

Pointing a client at Pooler is not always only a base-URL change. Each preset matches specific methods, paths, content types, and headers, and a request that does not match is refused rather than guessed at. Configure the client to satisfy the contract below before reporting that a setup works.

Two requirements apply to every preset:

- **Plain HTTP on loopback.** Every listener binds `127.0.0.1` over HTTP. A client that requires HTTPS, pins a certificate, or rejects a non-TLS base URL cannot reach Pooler until that is relaxed for the local address.
- **A placeholder credential where the client demands one.** Some clients refuse to start without an API key field. Use a non-secret placeholder; Pooler selects the real upstream credential server-side and strips client-supplied credential headers.

Pooler cannot change a client's own settings, and the setting names differ between clients and versions. Read the client's documentation for the current names, and confirm with the operator rather than guessing.

Verify what Pooler is actually matching before blaming the client:

```sh
pooler routes
pooler endpoint-inventory
```

### Devin

Devin must speak **Connect with protobuf**, not gRPC, gRPC-Web, or Connect+JSON. The chat route matches `application/connect+proto` exactly, and its `loss_policy` is `reject`, so a request Pooler cannot represent faithfully fails instead of degrading.

| Requirement | Value |
| :--- | :--- |
| Chat | `POST /exa.api_server_pb.ApiServerService/GetChatMessage`, `application/connect+proto` |
| Model discovery | `POST /exa.api_server_pb.ApiServerService/GetCliModelConfigs`, `application/proto` or `application/protobuf` |
| Seat and team | `POST /exa.seat_management_pb.SeatManagementService/GetUserStatus` and `.../GetCliTeamSettings` |
| Auth | `POST /exa.auth_pb.AuthService/GetUserJwt` |
| Analytics | `POST /exa.product_analytics_pb.ProductAnalyticsService/BatchRecordAnalyticsEvents` |
| Identity | `GET` or `POST /v3/self`, `application/json` |

Send all of these to the same base address. A client configured to send only chat traffic to Pooler while leaving auth, seat, or analytics calls pointed at their default host will not exercise the mounted routes, and the session may fail for reasons unrelated to inference.

### Factory Droid

Factory requires request **headers**, not just a base URL. The adapter rejects a request that omits or contradicts them:

| Header | Requirement |
| :--- | :--- |
| `ai-language-model-id` | Required, non-empty. Carries the model; Factory does not put the model in the body. |
| `ai-language-model-specification-version` | `3` or `4`. Defaults to `3` when absent. Any other value is rejected. |
| `ai-language-model-streaming` | Must be `true` when present. `false` is rejected, because the route requires streaming. |
| `ai-gateway-protocol-version` | Required when the specification version is `4`, and must be `0.0.1`. Rejected on version `3`. |

So **streaming must be enabled** in the client. A Factory client configured for unary responses is refused with a clear error rather than silently downgraded.

Routes matched: `POST /v3/ai/language-model` and `POST /v4/ai/language-model` (`application/json`), plus `GET /v3/ai/config` and `GET /v4/ai/config`.

### Cursor

Cursor needs only its OpenAI base URL and a placeholder key. The preset matches `POST` with any path prefix and `application/json`, so no additional client flag is required.

### Vercel Labs fx

fx matches `POST /v3/ai/language-model` and `POST /v4/ai/language-model` for inference, and `GET /coding-agent/v1/models` and `GET /v1/models` for discovery. The discovery routes use `loss_policy: reject`. Factory Droid is a separate client and does not use this adapter.

### OpenAI, Anthropic, and Gemini SDKs

Set the SDK's base URL and leave everything else alone. The `gateway` preset mounts the endpoint families each SDK expects. An SDK that appends its own version prefix needs the base URL that leaves the final path matching the table in [gateway](gateway.md); confirm with `pooler routes` if a call returns `404`.

---

## `cursor`

Forwards Cursor's JSON requests and rewrites the request body before it reaches the upstream. `reasoning_effort` sets the value written to `/reasoning_effort`, and `model_prefix` restricts which model names receive it.

```yaml
version: 2

imports:
  - preset: cursor
    as: cursor-adapter
    with:
      bind: 127.0.0.1:8333
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
      model_prefix: gpt-
      reasoning_effort: high
```

Point Cursor's OpenAI base URL at `http://127.0.0.1:8333`.

## `devin`

Translates Devin's ConnectRPC protobuf calls into OpenAI chat completions and encodes the streamed reply back into ConnectRPC envelopes. Its `loss_policy` is `reject`, so a request that cannot be represented faithfully fails instead of degrading silently.

```yaml
version: 2

imports:
  - preset: devin
    as: devin-bridge
    with:
      bind: 127.0.0.1:18473
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
```

The preset mounts the chat bridge on `/exa.api_server_pb.ApiServerService/GetChatMessage` and forwards the model-config, seat-management, auth, analytics, and `/v3/self` surfaces unchanged.

## `factory`

Translates Factory Droid's `/v3/ai/language-model` and `/v4/ai/language-model` requests into OpenAI chat completions and re-encodes the event stream. Its `loss_policy` is `degrade`. The `/v3/ai/config` and `/v4/ai/config` routes are forwarded unchanged.

```yaml
version: 2

imports:
  - preset: factory
    as: factory-adapter
    with:
      bind: 127.0.0.1:18474
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
```

Point Factory Droid at `http://127.0.0.1:18474`.

## `fx`

Serves the native Vercel Labs fx adapter, including model discovery, streaming, and tool-result continuation. Factory Droid is a separate client and does not use this adapter. See [fx](fx.md).

```yaml
version: 2

imports:
  - preset: fx
    as: fx-runtime
    with:
      bind: 127.0.0.1:18475
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
```

## `xai`

Routes xAI Grok traffic across separate REST and WebSocket transports.

```yaml
version: 2

imports:
  - preset: xai
    as: xai-gateway
    with:
      bind: 127.0.0.1:18476
      rest_url: https://api.x.ai
      secret: env:XAI_API_KEY
```

## `media`

Mounts bounded OpenAI-style image, audio, file, embedding, and batch surfaces without claiming cross-provider translation. Most provider-native request and response bodies stay opaque. Multipart image edits, audio transcriptions, and file uploads are decoded only for strict validation and capability-aware selection; Pooler forwards the original boundary, headers, field order, and body bytes unchanged.

```yaml
version: 2

imports:
  - preset: media
    as: media
    with:
      bind: 127.0.0.1:18476
      upstream_url: http://127.0.0.1:8319
      secret: env:POOLER_UPSTREAM_KEY
```

The preset caps image, audio, and file requests at 32 MiB and embedding and batch requests at 8 MiB. Opaque bodies stream once and cannot be replayed. Multipart bodies are buffered within the configured limit for validation; the normal method/idempotency, commitment, and retry budgets determine whether a buffered request can be retried. The default bind is also used by `xai`; change one `bind` if both presets are imported.

## `gateway`

Mounts the endpoint families a general OpenAI, Anthropic, or Gemini client expects. The upstream is declared with `known_provider`, so its base URL, discovery parser, model aliases, and exclusions come from the shipped provider catalog.

```yaml
version: 2

imports:
  - preset: gateway
    as: gateway
    with:
      bind: 127.0.0.1:8400
      secret: env:POOLER_GATEWAY_KEY
```

Routes use one of two modes. In `patch` mode Pooler preserves the caller's JSON body and rewrites only the `/model` pointer, which is what makes catalog aliases, account pooling, and capability filtering apply. In `opaque` mode bytes and frames are forwarded without semantic decoding, so media, file, and batch surfaces keep provider-specific fields exactly.

Opaque forwarding is not protocol translation. A route only translates between protocols when it declares an explicit decoder and encoder.

Set `websocket_url` whenever `provider` is not `openai`, because a WebSocket route needs an explicit `ws`/`wss` transport that cannot be derived from `known_provider`. See [gateway](gateway.md) for the full route inventory.

---

## Verify a preset

Expand imports and confirm the compiled result before serving:

```sh
pooler check --config config/your-config.yaml
pooler --config config/your-config.yaml config render
pooler --config config/your-config.yaml routes
```

`config render` prints the fully expanded configuration without resolving secrets. `routes` lists the compiled routes in match order.
