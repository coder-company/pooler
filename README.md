<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/mark-white-128.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/mark-charcoal-128.png">
  <img alt="Pooler by Coder Company" src="assets/mark-charcoal-128.png" width="88" height="78">
</picture>

# Pooler
**by Coder Company**

### Use your ChatGPT / Codex subscription across all your AI coding tools.

[![License](https://img.shields.io/badge/license-Apache--2.0-black?style=flat-square)](LICENSE)
[![Built for Agents](https://img.shields.io/badge/agent--native-llms.txt-10B981?style=flat-square)](llms.txt)
[![Rust](https://img.shields.io/badge/runtime-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Mintlify](https://img.shields.io/badge/docs-Mintlify-059669?style=flat-square)](mint.json)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-blue?style=flat-square)](docs/deployment.md)

[**Quick Install**](#-quick-install) · [**Codex Subscription Setup**](#-connect-your-codex-subscription) · [**Agent Prompts**](#-agent-native-setup) · [**Dashboard**](#-management-dashboard) · [**Adapters**](#-adapters--presets) · [**llms.txt**](llms.txt)

---

</div>

## What is Pooler?

**Pooler** is a local proxy that unlocks your **ChatGPT / Codex subscriptions** and provider accounts for all your coding tools—**Cursor**, **Devin**, **Factory Droid**, **Claude Code**, and standard AI SDKs.

Instead of paying for separate API keys for every tool or hitting individual account limits, Pooler gives you one local endpoint that:
- **Routes any tool to your Codex subscription**: Translate Cursor, Devin ConnectRPC, and Factory Droid requests to your OpenAI / Codex subscription.
- **Pools multiple subscriptions & accounts**: Connect multiple accounts. When one account hits a rate limit or hourly quota, Pooler fails over to the next account automatically.
- **Brokered OAuth & device flow**: Log in with one click in the web dashboard or with `pooler auth login openai --method device-code`. No copying raw tokens or leaking keys in plaintext.
- **Real-time usage & dashboard**: Inspect live request timelines, time-to-first-token (TTFT), quota cooldowns, and token ledgers on `http://127.0.0.1:18477`.

```
+---------------------------------------------------------------------------------------+
|                              Your Coding Tools & Agents                               |
|        Cursor (:8333) | Devin (:18473) | Factory Droid (:18474) | SDKs (:8400)        |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                                  Pooler Local Runtime                                 |
|  +------------------------------------+  +-----------------------------------------+  |
|  | Protocol & Presets Translation     |  | Codex Account Pooling & Quota Cooldowns |  |
|  | - JSON Patch (Cursor)              |  | - Automatic failover on usage limits    |  |
|  | - ConnectRPC Protobuf (Devin)      |  | - Multi-subscription rotation           |  |
|  | - Factory v3/v4 Language Model     |  | - AES-GCM encrypted token persistence   |  |
|  +------------------------------------+  +-----------------------------------------+  |
|                                                                                       |
|  +---------------------------------------------------------------------------------+  |
|  | Web Management Dashboard (:18477) · Request Timelines · Real-time Usage Ledger  |  |
|  +---------------------------------------------------------------------------------+  |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                           Your Subscriptions & Providers                              |
|           ChatGPT / Codex Subscriptions | Claude | Gemini | Grok | Custom             |
+---------------------------------------------------------------------------------------+
```

---

## ⚡ Quick Install

Install the standalone Pooler binary via script:

```sh
curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
```

*Or install via Cargo:*
```sh
cargo install --git https://github.com/coder-company/pooler.git pooler-cli --bin pooler
```

---

## 🔑 Connect Your Codex Subscription

### Option A: 1-Click Login via Web Dashboard (Recommended)

1. **Start the starter deployment**:
   ```sh
   pooler init --output pooler-starter
   pooler --config pooler-starter/pooler.yaml serve
   ```
2. **Open the dashboard**:
   ```sh
   pooler --config pooler-starter/pooler.yaml dashboard
   ```
3. Go to **Accounts** → **Connect** → **Start device authorization**. Complete the OpenAI prompt in your browser.

### Option B: Quick CLI Device Login

Log into your OpenAI / Codex subscription directly in your terminal:

```sh
pooler --config pooler-starter/pooler.yaml auth login openai --method device-code
```

Open the printed verification URL, enter the one-time user code, and authorize. Tokens are saved directly to encrypted local SQLite.

### Option C: Import Existing Codex CLI Credentials

If you already use Codex locally, import your existing credentials:

```sh
pooler --config pooler-starter/pooler.yaml auth import my-codex --profile codex --from-file ~/.codex/credentials.json
```

---

## 🤖 Agent-Native Setup

Just copy any prompt below and give it to your coding agent (**Cursor**, **Devin**, **Claude Code**, **Codex**, or **Factory Droid**) to let it configure Pooler for you:

| Goal | Copy-Paste Agent Prompt |
| :--- | :--- |
| **Setup Codex Subscription** | `"Initialize Pooler with 'pooler init', run device login for my OpenAI Codex subscription via 'pooler auth login openai --method device-code', and start the proxy."` |
| **Configure Cursor Preset** | `"Configure Pooler for Cursor on port 8333 routing to my Codex subscription with reasoning_effort set to high. Verify with pooler check."` |
| **Configure Devin Preset** | `"Configure Pooler with the Devin ConnectRPC preset on port 18473 translating to my pooled Codex subscription accounts."` |
| **Configure Factory Droid** | `"Configure Pooler with the Factory preset on port 18474 to bridge /v3/ai and /v4/ai language model requests to Codex."` |
| **Multi-Subscription Pooling** | `"Configure Pooler to pool 2 OpenAI Codex subscription accounts with automatic failover on rate limits and quota cooldowns."` |
| **Run System Diagnostics** | `"Run 'pooler doctor' and 'pooler preflight' to verify listener ports, TLS handshakes, and credential stores."` |

👉 *Full agent prompt cookbook available in [`llms.txt`](llms.txt) and [`docs/agent-native.md`](docs/agent-native.md).*

---

## 🔌 Adapters & Presets

| Preset | Target Client | Default Bind | Purpose |
| :--- | :--- | :--- | :--- |
| [`cursor`](docs/adapters-and-presets.md#1-cursor-preset-cursor) | Cursor IDE | `127.0.0.1:8333` | Rewrites model prefixes and injects reasoning effort. |
| [`devin`](docs/adapters-and-presets.md#2-devin-connectrpc-preset-devin) | Devin | `127.0.0.1:18473` | Translates ConnectRPC protobuf to OpenAI completions. |
| [`factory`](docs/adapters-and-presets.md#3-factory-droid-preset-factory) | Factory Droid | `127.0.0.1:18474` | Translates `/v3/ai` and `/v4/ai` endpoints. |
| [`gateway`](docs/gateway.md) | Multi-provider | `127.0.0.1:8400` | Unified OpenAI, Anthropic, and Gemini endpoint family. |
| [`fx`](docs/fx.md) | Vercel Labs fx | `127.0.0.1:18475` | Streaming inference and tool-result continuation. |
| [`xai`](docs/adapters-and-presets.md#6-xai-grok-preset-xai) | xAI Grok | `127.0.0.1:18476` | Native Grok routing with live search integration. |

---

## 📊 Management Dashboard

Pooler includes an authenticated management web dashboard running on `http://127.0.0.1:18477`:

- **Overview**: Active configuration generation, listener status, route inventory, and health status.
- **Live Request Explorer**: Per-request timeline correlating admission, route selection, TTFT, retries, and token usage.
- **Accounts & Failover**: Manage Codex subscription logins, OAuth refresh tokens, and pool failover priority.
- **Historical Usage Ledger**: Multidimensional time-range analytics for input/output/reasoning tokens and USD costs.
- **Operations & Hot Reload**: Reload configuration in memory (`POST /reload`) without dropping active connections.

---

## 📚 Documentation

| Resource | Description |
| :--- | :--- |
| [**Overview**](docs/index.md) | Architectural deep-dive, security boundaries, and data flow. |
| [**Agent Native Guide**](docs/agent-native.md) | Complete prompt cookbook for AI coding agents. |
| [**Quickstart**](docs/quickstart.md) | 3-minute starter guide with Codex subscription login. |
| [**CLI Reference**](docs/cli-reference.md) | Complete reference for all subcommands, arguments, and flags. |
| [**Adapters & Presets**](docs/adapters-and-presets.md) | Presets for Cursor, Devin, Factory Droid, and Gateways. |
| [**Provider Login & Auth**](docs/provider-login.md) | Device OAuth, browser PKCE, and encrypted SQLite storage. |
| [**Management & Dashboard**](docs/management.md) | REST management API, request timeline explorer, and usage ledger. |
| [**Troubleshooting & Doctor**](docs/troubleshooting.md) | Diagnostic checks and preflight network verification. |
| [**Production Deployment**](docs/deployment.md) | Docker, docker-compose, and systemd units. |
| [**llms.txt**](llms.txt) | Curated agent-native project index. |

---

<div align="center">

**Built with precision by Coder Company**

[Report Issue](https://github.com/coder-company/pooler/issues) · [Discussions](https://github.com/coder-company/pooler/discussions) · [Documentation](docs/index.md)

</div>
