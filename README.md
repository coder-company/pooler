<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/mark-white-128.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/mark-charcoal-128.png">
  <img alt="Pooler by Coder Company" src="assets/mark-charcoal-128.png" width="88" height="78">
</picture>

# Pooler
**by Coder Company**

### The protocol runtime and pooling proxy for AI coding agents, subscriptions, and providers.

[![License](https://img.shields.io/badge/license-Apache--2.0-black?style=flat-square)](LICENSE)
[![Built for Agents](https://img.shields.io/badge/agent--native-llms.txt-10B981?style=flat-square)](llms.txt)
[![Rust](https://img.shields.io/badge/runtime-Rust-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Mintlify](https://img.shields.io/badge/docs-Mintlify-059669?style=flat-square)](mint.json)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-blue?style=flat-square)](docs/deployment.md)

[**Quick Install**](#-quick-install) · [**Agent Prompts**](#-1-agent-native-setup-primary) · [**Connect Accounts & Subscriptions**](#-2-connect-subscriptions--provider-apis) · [**Dashboard**](#-management-dashboard) · [**Adapters**](#-adapters--presets) · [**llms.txt**](llms.txt)

---

</div>

## What is Pooler?

**Pooler** is a local proxy that connects your AI coding tools (**Cursor**, **Devin**, **Factory Droid**, **Claude Code**, and standard AI SDKs) to your **subscriptions** (ChatGPT / Codex) and **model provider APIs** (OpenAI, Anthropic Claude, Google Gemini, xAI Grok, custom providers).

- **One local endpoint for all tools**: Direct your coding tools to a single local port. Pooler translates request formats and wire protocols automatically.
- **Account pooling & automatic failover**: Connect multiple subscriptions or API keys. When one hits a rate limit or hourly quota, Pooler switches to the next available account instantly.
- **Brokered OAuth & safe credentials**: Log in with one-click device OAuth or browser PKCE. Credentials stay encrypted in local SQLite (`AES-GCM`) instead of leaking plaintext keys.
- **Real-time web dashboard**: Inspect live request timelines, time-to-first-token (TTFT), cooldowns, token counts, and cost ledgers on `http://127.0.0.1:18477`.

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
|  | Protocol & Presets Translation     |  | Multi-Account Pooling & Quota Cooldowns |  |
|  | - JSON Patch (Cursor)              |  | - Fill-first / round-robin selection   |  |
|  | - ConnectRPC Protobuf (Devin)      |  | - Automatic rate-limit retry & failover |  |
|  | - Factory v3/v4 Language Model     |  | - Encrypted SQLite token persistence   |  |
|  +------------------------------------+  +-----------------------------------------+  |
|                                                                                       |
|  +---------------------------------------------------------------------------------+  |
|  | Web Management Dashboard (:18477) · Request Timelines · Real-time Usage Ledger  |  |
|  +---------------------------------------------------------------------------------+  |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                           Your Subscriptions & Provider APIs                          |
|         ChatGPT / Codex Subscriptions | Claude | Gemini | xAI Grok | Custom           |
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

## 🤖 1. Agent-Native Setup (Primary)

Pooler is built agent-native. Copy any prompt below and give it directly to your coding agent (**Cursor**, **Devin**, **Claude Code**, **Codex**, or **Factory Droid**):

| Goal | Copy-Paste Agent Prompt |
| :--- | :--- |
| **Setup Codex Subscription** | `"Initialize Pooler with 'pooler init', run device login for my OpenAI Codex subscription via 'pooler auth login openai --method device-code', and start the proxy."` |
| **Setup Google Gemini OAuth** | `"Authenticate Google Gemini in Pooler via browser PKCE OAuth using 'pooler auth login google --method oauth' and verify credentials."` |
| **Configure Cursor Preset** | `"Configure Pooler for Cursor on port 8333 routing to my accounts with reasoning_effort set to high. Verify with pooler check."` |
| **Configure Devin Preset** | `"Configure Pooler with the Devin ConnectRPC preset on port 18473 translating to my pooled provider accounts."` |
| **Configure Factory Droid** | `"Configure Pooler with the Factory preset on port 18474 to bridge /v3/ai and /v4/ai language model requests."` |
| **Multi-Account Pooling & Failover** | `"Configure Pooler to pool multiple subscriptions and API keys with automatic failover on rate limits and quota cooldowns."` |
| **Configure Universal Gateway** | `"Set up a universal gateway on port 8400 routing OpenAI, Claude, and Gemini requests with account pooling."` |
| **Migrate from CLIProxyAPI** | `"Run 'pooler migrate cliproxy config.yaml --dry-run' and output the validated configuration to migrated.pooler.yaml."` |
| **Run System Diagnostics** | `"Run 'pooler doctor' and 'pooler preflight' to verify listener ports, TLS handshakes, and credential stores."` |

👉 *Full agent prompt cookbook available in [`llms.txt`](llms.txt) and [`docs/agent-native.md`](docs/agent-native.md).*

---

## 🔑 2. Connect Subscriptions & Provider APIs

### Option A: ChatGPT / Codex Subscription (Device OAuth)
```sh
pooler --config pooler-starter/pooler.yaml auth login openai --method device-code
```
*Open the verification URL, enter the one-time code, and authorize. Tokens are encrypted in local SQLite.*

### Option B: Google Gemini (Browser PKCE OAuth)
```sh
pooler --config pooler-starter/pooler.yaml auth login google --method oauth
```

### Option C: Provider API Keys (Anthropic Claude, OpenAI, xAI Grok)
Set your environment variables or store them in owner-private files (`0600`):
```sh
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export XAI_API_KEY="xai-..."
```
*Pooler resolves secrets securely via `env:`, `file:`, or OS `keyring:` references.*

### Option D: 1-Click Login via Web Dashboard
1. Start the proxy: `pooler --config pooler-starter/pooler.yaml serve`
2. Open the dashboard: `pooler --config pooler-starter/pooler.yaml dashboard`
3. Go to **Accounts** → **Connect** to authenticate subscriptions or add keys.

---

## 📊 Management Dashboard

Pooler includes an authenticated management web dashboard running on `http://127.0.0.1:18477`:

- **Overview**: Active configuration generation, listener status, route inventory, and health status.
- **Live Request Explorer**: Per-request timeline correlating admission, route selection, TTFT, retries, and token usage.
- **Accounts & Failover**: Manage subscriptions, API keys, OAuth refresh tokens, and pool failover priority.
- **Historical Usage Ledger**: Multidimensional time-range analytics for input/output/reasoning tokens and USD costs.
- **Operations & Hot Reload**: Reload configuration in memory (`POST /reload`) without dropping active connections.

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

## 📚 Documentation

| Resource | Description |
| :--- | :--- |
| [**Overview**](docs/index.md) | Architectural deep-dive, security boundaries, and data flow. |
| [**Agent Native Guide**](docs/agent-native.md) | Complete prompt cookbook for AI coding agents. |
| [**Quickstart**](docs/quickstart.md) | 3-minute starter guide with subscription and API key login. |
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
