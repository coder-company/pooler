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
