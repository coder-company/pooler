# Pooler

Pooler is a local proxy that connects your AI coding tools (Cursor, Devin, Factory Droid, Claude Code, and standard AI SDKs) to AI model providers (OpenAI, Anthropic Claude, Google Gemini, xAI Grok).

It gives you one local endpoint that translates request formats, rotates across multiple accounts when you hit rate limits, handles OAuth logins safely, and gives you a local web dashboard to monitor requests and costs.

```
+-----------------------------------------------------------------------+
|  Your Coding Tools & Agents                                           |
|  Cursor (8333) | Devin (18473) | Factory Droid (18474) | SDKs (8400)  |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Pooler (Local Proxy)                                                 |
|  - Translates protocols (ConnectRPC, Factory, OpenAI, Claude, Gemini)  |
|  - Pools multiple accounts & handles rate limits automatically        |
|  - Stores credentials safely in encrypted SQLite                      |
|  - Shows live requests & token usage in a local web dashboard         |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  AI Providers                                                         |
|  OpenAI | Anthropic Claude | Google Gemini | xAI Grok | Custom        |
+-----------------------------------------------------------------------+
```

---

## 3-Minute quickstart

### 1. Initialize starter configuration
```sh
pooler init --output pooler-starter
```

### 2. Add your provider API key
```sh
echo "sk-your-actual-api-key-here" > pooler-starter/provider.key
chmod 0600 pooler-starter/provider.key
```
*(Or log in via OAuth: `pooler --config pooler-starter/pooler.yaml auth login openai --method device-code`)*

### 3. Check configuration & network
```sh
pooler check --config pooler-starter/pooler.yaml
pooler --config pooler-starter/pooler.yaml preflight
```

### 4. Start the server
```sh
pooler --config pooler-starter/pooler.yaml \
  --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  serve
```

### 5. Open the dashboard
In another terminal, run:
```sh
pooler --config pooler-starter/pooler.yaml dashboard
```

---

## Agent-native setup

Instead of configuring things manually, copy these prompts into your coding agent:

- **Full Prompt Library**: See [Agent Native Prompts](docs/agent-native.md) and [`llms.txt`](llms.txt).
- **Cursor Setup**: *"Configure Pooler with the Cursor preset on port 8333 with high reasoning effort."*
- **Devin Setup**: *"Configure Pooler to translate Devin ConnectRPC requests on port 18473 to OpenAI."*
- **Factory Droid Setup**: *"Configure Pooler for Factory Droid language-model routes on port 18474."*
- **Multi-Account Pooling**: *"Set up account pooling across 3 OpenAI accounts with automatic failover."*

---

## Adapters and presets

| Preset | Tool / Agent | Port | What it does |
| :--- | :--- | :--- | :--- |
| [`cursor`](docs/adapters-and-presets.md#1-cursor-preset-cursor) | Cursor IDE | `8333` | Rewrites model prefixes and injects reasoning parameters. |
| [`devin`](docs/adapters-and-presets.md#2-devin-connectrpc-preset-devin) | Devin | `18473` | Translates Devin ConnectRPC protobuf requests to OpenAI Chat. |
| [`factory`](docs/adapters-and-presets.md#3-factory-droid-preset-factory) | Factory Droid | `18474` | Translates Factory `/v3/ai` and `/v4/ai` requests to OpenAI Chat. |
| [`gateway`](docs/gateway.md) | Multi-provider | `8400` | Unified OpenAI, Anthropic, and Gemini endpoint. |
| [`fx`](docs/fx.md) | Vercel Labs fx | `18475` | Vercel Labs fx tool continuation and streaming runtime. |
| [`xai`](docs/adapters-and-presets.md#6-xai-grok-preset-xai) | xAI Grok | `18476` | Grok model routing with live search and reasoning support. |

---

## Documentation

- [Overview](docs/index.md): Architecture, features, and how it works.
- [Quickstart](docs/quickstart.md): 3-minute setup guide.
- [Agent Native Guide](docs/agent-native.md): Copy-paste prompt cookbook for AI agents.
- [CLI Reference](docs/cli-reference.md): All commands, options, and flags.
- [Adapters & Presets](docs/adapters-and-presets.md): Presets for Cursor, Devin, Factory, and gateways.
- [Provider Login & Auth](docs/provider-login.md): Device OAuth, browser PKCE, and encrypted credentials.
- [Management & Dashboard](docs/management.md): Web dashboard, request timeline, and usage ledger.
- [Troubleshooting & Doctor](docs/troubleshooting.md): Diagnosis checks and preflight network tests.
- [Deployment Guide](docs/deployment.md): Run with Docker, docker-compose, and systemd.
