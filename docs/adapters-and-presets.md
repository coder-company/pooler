# Adapters and presets

Pooler includes built-in presets that configure listeners, routing rules, request/response decoders, and semantic transformations for AI coding agents and standard protocols.

## Using presets in configuration

Import a preset using the `imports` list in your `pooler.yaml`:

```yaml
version: 2

imports:
  - preset: <PRESET_NAME>
    as: <UNIQUE_NAMESPACE>
    with:
      bind: <LISTEN_ADDRESS>
      upstream_url: <UPSTREAM_ADDRESS>
      secret: <SECRET_REF>
```

---

## Supported presets

### 1. Cursor preset (`cursor`)

Configures an ingress proxy tailored for Cursor IDE requests. It applies JSON patching rules to rewrite model prefixes and dynamically adjust reasoning parameters.

```yaml
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

- **Default bind**: `127.0.0.1:8333`
- **Protocol**: OpenAI-compatible HTTP POST `/`
- **Transforms**: Inspects OpenAI model names and sets `reasoning_effort` for matching model prefixes.

### 2. Devin ConnectRPC preset (`devin`)

Provides a semantic bridge translating Devin protobuf ConnectRPC requests into upstream OpenAI chat completion requests, and translates streaming completions back into ConnectRPC envelopes.

```yaml
imports:
  - preset: devin
    as: devin-bridge
    with:
      bind: 127.0.0.1:18473
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
```

- **Default bind**: `127.0.0.1:18473`
- **Key routes**:
  - `POST /exa.api_server_pb.ApiServerService/GetChatMessage`: ConnectRPC semantic bridge (`decode.devin.chat` → `decode.openai.chat.events` → `encode.devin.connect`).
  - `POST /exa.api_server_pb.ApiServerService/GetCliModelConfigs`: Model config forwarding.
  - `POST /exa.seat_management_pb.SeatManagementService/GetUserStatus`: Seat status passthrough.
  - `POST /exa.auth_pb.AuthService/GetUserJwt`: Auth token handling.
  - `GET, POST /v3/self`: Identity passthrough.

### 3. Factory Droid preset (`factory`)

Translates Factory Droid language-model requests (`/v3/ai/language-model`, `/v4/ai/language-model`) to OpenAI `/v1/chat/completions` and encodes event streams back to Factory SSE format.

```yaml
imports:
  - preset: factory
    as: factory-adapter
    with:
      bind: 127.0.0.1:18474
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
```

- **Default bind**: `127.0.0.1:18474`
- **Key routes**:
  - `POST /v3/ai/language-model` & `POST /v4/ai/language-model`: Decodes Factory JSON format and encodes streaming completions.
  - `GET /v3/ai/config` & `GET /v4/ai/config`: Passes through model configuration endpoints.

### 4. Vercel Labs fx preset (`fx`)

Integrates with the Vercel Labs fx execution runtime, providing model discovery, streaming inference, and tool-result continuation.

```yaml
imports:
  - preset: fx
    as: fx-runtime
    with:
      bind: 127.0.0.1:18475
      upstream_url: https://api.openai.com
      secret: env:OPENAI_API_KEY
```

- **Details**: See [Vercel Labs fx guide](fx.md) for tool-result continuations and streaming options.

### 5. Multi-provider Gateway preset (`gateway`)

Mounts the standard endpoint families expected by OpenAI, Anthropic, Gemini, and general AI SDKs without requiring hand-authored route plans.

```yaml
imports:
  - preset: gateway
    as: gateway
    with:
      bind: 127.0.0.1:8400
      upstream_url: https://api.openai.com
      websocket_url: wss://api.openai.com
      secret: env:POOLER_GATEWAY_KEY
```

- **Default bind**: `127.0.0.1:8400`
- **Supported endpoints**:
  - `/v1/chat/completions` (OpenAI format)
  - `/v1/messages` (Anthropic format)
  - `/v1beta/models/*` (Gemini format)
  - `/v1/models` (Catalog listing)
  - `/v1/embeddings`, `/v1/audio/*`, `/v1/images/*` (Multi-modal routes)

### 6. xAI Grok preset (`xai`)

Configures optimized routing for xAI Grok models with reasoning parameters and native live search integration.

```yaml
imports:
  - preset: xai
    as: xai-gateway
    with:
      bind: 127.0.0.1:18476
      upstream_url: https://api.x.ai
      secret: env:XAI_API_KEY
```

---

## Verifying preset compilation

To inspect the fully expanded routes and transforms created by presets:

```sh
pooler --config config/your-config.yaml config render
pooler --config config/your-config.yaml routes
```
