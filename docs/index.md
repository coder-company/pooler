# Pooler

Pooler is a local protocol runtime and pooling proxy by Coder Company. It connects your AI coding tools (**Cursor**, **Devin**, **Factory Droid**, **Claude Code**, and standard AI SDKs) to your **ChatGPT / Codex subscriptions** and **model provider APIs** (OpenAI, Anthropic Claude, Google Gemini, xAI Grok, and custom providers).

```
+-----------------------------------------------------------------------+
|  Your Coding Tools & Agents                                           |
|  Cursor (8333) | Devin (18473) | Factory Droid (18474) | SDKs (8400)  |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Pooler (Local Runtime)                                               |
|  - Translates protocols (ConnectRPC, Factory, OpenAI, Claude, Gemini)  |
|  - Pools multiple subscriptions & API keys with automatic failover    |
|  - Stores credentials safely in encrypted SQLite                      |
|  - Shows live requests & token usage in a local web dashboard         |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  Subscriptions & AI Providers                                         |
|  ChatGPT / Codex Subscriptions | Claude | Gemini | xAI Grok | Custom  |
+-----------------------------------------------------------------------+
```

---

## Why use Pooler?

1. **One local endpoint for all your tools**: Point Cursor, Devin, Factory Droid, or standard Python/Node SDKs to Pooler. Pooler translates request formats automatically so your tools can talk to any provider or subscription.
2. **Account pooling and automatic failover**: Connect multiple subscriptions or API keys for OpenAI, Claude, or Gemini. When one hits a rate limit or hourly quota, Pooler switches to the next available account.
3. **Safe authentication**: Log in using official provider OAuth (like OpenAI Codex device login or Google OAuth) without copying tokens into plaintext config files. Credentials stay encrypted in a local SQLite database (`AES-GCM`).
4. **Agent-native setup**: Configure integrations by copying short task prompts into your coding agent (Cursor, Devin, Claude Code) and letting the agent configure everything for you.
5. **Built-in dashboard**: Run `pooler dashboard` to watch live requests, latency, time-to-first-token (TTFT), token counts, and cost estimates on `http://127.0.0.1:18477`.

---

## How it works in 3 steps

### Step 1: Initialize
Run `pooler init` to create an owner-private setup folder with safe defaults:
```sh
pooler init --output pooler-starter
```

### Step 2: Connect your subscription or API key
Log in using the official device OAuth flow:
```sh
pooler --config pooler-starter/pooler.yaml auth login openai --method device-code
```
*(Or write your API key to `pooler-starter/provider.key`)*

### Step 3: Start serving and connect your tool
Start the proxy:
```sh
pooler --config pooler-starter/pooler.yaml serve
```
Then point your tool (like Cursor or your Python script) to `http://127.0.0.1:8319` (or `http://127.0.0.1:8400`).

---

## Documentation guides

| Guide | What you will learn |
| :--- | :--- |
| [Agent Native Guide](agent-native.md) | Ready-made prompts for Cursor, Devin, and coding agents to configure Pooler for you. |
| [Quickstart](quickstart.md) | Set up and run Pooler in under 3 minutes. |
| [Adapters & Presets](adapters-and-presets.md) | Pre-built configurations for Cursor, Devin, Factory Droid, and multi-provider gateways. |
| [CLI Reference](cli-reference.md) | Complete list of all commands, options, and flags. |
| [Provider Login & Auth](provider-login.md) | How to log into OpenAI, Claude, Google Gemini, and manage accounts. |
| [Management & Dashboard](management.md) | How to use the local web dashboard, live request explorer, and usage ledger. |
| [Troubleshooting](troubleshooting.md) | Run `pooler doctor` and `pooler preflight` to fix common setup issues. |
| [Production Deployment](deployment.md) | Run Pooler with Docker, docker-compose, or systemd. |
