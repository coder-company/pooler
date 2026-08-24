# Agent-Native Setup Guide

Pooler is a **system-wide AI proxy and account pooling daemon** by Coder Company. Once installed on your machine, it runs in the background and serves all your AI coding tools (Cursor, Devin, Factory Droid, Claude Code, and terminal SDKs) across all your projects and repositories.

---

## 1. What the User Pastes to Their Agent (Initiation Prompt)

Copy and paste this prompt into any AI coding agent (Cursor, Devin, Claude Code, Factory Droid, Codex):

```text
Set up and configure Pooler system-wide on my machine from https://github.com/coder-company/pooler:
1. First, ask me using your interactive question tool:
   - Which coding tools/agents I use on this machine (Cursor, Devin, Factory Droid, Claude Code / Codex, or general SDKs).
   - What credentials/subscriptions I want to connect (ChatGPT / Codex subscription via device OAuth, Google Gemini OAuth, Anthropic Claude API key, OpenAI API key, xAI Grok, or Custom).
   - Whether I want multi-account pooling with automatic rate-limit failover across my subscriptions.
   - What specific models or reasoning settings I want enabled (e.g. gpt-4o, claude-3-7-sonnet, gemini-2.5-pro, o3-mini with high reasoning).
2. Fetch documentation and recipes from https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt or inspect the repository at https://github.com/coder-company/pooler.
3. Install the Pooler binary if not already present:
   `curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash`
4. Set up the system-wide configuration at ~/.config/pooler/pooler.yaml.
5. Guide me through authenticating my subscriptions (such as running `pooler auth login openai --method device-code` for Codex subscriptions or setting environment variables).
6. Run `pooler check` and `pooler preflight` to verify system-wide setup.
7. Start the system-wide daemon with `pooler serve` (or enable background service) and verify with `pooler dashboard`.
8. Provide the exact local connection URLs for all my coding tools.
```

---

## 2. Agent Execution System Prompt (Instructions for Agents)

When an AI agent receives the initiation prompt, it executes the following system-wide protocol:

```markdown
### Agent Protocol for System-Wide Pooler Setup

Repository: https://github.com/coder-company/pooler
Agent Index: https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt

#### Step 1: Interactive User Inquiry (Mandatory)
Before writing any configuration files or running commands, interactively prompt the user (using structured selection tools like AskQuestion when available):
1. **Target Tools & Presets**:
   - Cursor IDE (port 8333)
   - Devin ConnectRPC (port 18473)
   - Factory Droid (port 18474)
   - Universal Gateway for Claude Code / Python / Node SDKs (port 8400)
2. **Authentication Method**:
   - ChatGPT / Codex Subscription (OAuth Device Flow)
   - Google Gemini (Browser PKCE OAuth)
   - Provider API Key (Anthropic, OpenAI, xAI, OpenRouter)
   - Multi-account / Multi-subscription Pooling
3. **Model & Parameter Preferences**:
   - Reasoning effort (e.g., `high` for o3/gpt models)
   - Fallback order and cooldown policies

#### Step 2: System Binary Installation
1. Check if `pooler` is available in PATH. If not, install system-wide:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
   ```
2. Ensure directory permissions:
   ```sh
   mkdir -p ~/.config/pooler
   chmod 0700 ~/.config/pooler
   ```

#### Step 3: Generate System-Wide Configuration (`~/.config/pooler/pooler.yaml`)
Create or update `~/.config/pooler/pooler.yaml` with the chosen presets and upstream providers:

```yaml
version: 2

imports:
  - preset: cursor
    as: cursor-adapter
    with:
      bind: 127.0.0.1:8333
      reasoning_effort: high

  - preset: gateway
    as: gateway
    with:
      bind: 127.0.0.1:8400

listeners:
  main:
    bind: 127.0.0.1:8319

management:
  bind: 127.0.0.1:18477
```

#### Step 4: Authenticate Subscriptions & Accounts
- For **ChatGPT / Codex Subscriptions**:
  Run:
  ```sh
  pooler auth login openai --method device-code
  ```
  Provide the verification URL and user code to the operator, wait for completion, and verify with `pooler auth status --provider openai`.
- For **Google Gemini OAuth**:
  Run:
  ```sh
  pooler auth login google --method oauth
  ```
- For **Importing Existing Codex CLI Credentials**:
  Run:
  ```sh
  pooler auth import my-codex --profile codex --from-file ~/.codex/credentials.json
  ```
- For **API Keys**:
  Set environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `XAI_API_KEY`) in shell profile.

#### Step 5: Validate and Start System Daemon
1. Validate syntax and network reachability:
   ```sh
   pooler check
   pooler preflight
   ```
2. Start the daemon in the background or foreground:
   ```sh
   pooler serve &
   ```
3. Open the web dashboard:
   ```sh
   pooler dashboard
   ```

#### Step 6: Provide Global Tool Configuration Instructions
Explain how to configure coding tools globally:
- **Cursor Settings**: Set OpenAI Base URL to `http://127.0.0.1:8333` (applies to all Cursor projects).
- **Devin Settings**: Set endpoint to `http://127.0.0.1:18473`.
- **Factory Droid Settings**: Set AI URL to `http://127.0.0.1:18474`.
- **Claude Code / Global SDKs**: Export in `~/.bashrc` or `~/.zshrc`:
  ```sh
  export OPENAI_BASE_URL="http://127.0.0.1:8400/v1"
  export ANTHROPIC_BASE_URL="http://127.0.0.1:8400"
  ```
```

---

## 3. Specific Action Prompts for Agents

### Pool Multiple Subscriptions for Zero-Downtime Rate Limits
```text
Task: Update my system-wide Pooler configuration to pool multiple ChatGPT / Codex subscriptions and API keys:
1. Edit ~/.config/pooler/pooler.yaml to add an account pool named `main-pool` with strategy `fill_first`.
2. Configure automatic retry with `maximum_attempts: 3` on HTTP 429 and 503 errors.
3. Validate the configuration using `pooler check` and restart or reload via `POST /reload`.
```

### Switch Active Account or Refresh Tokens
```text
Task: Switch my active provider account in Pooler:
1. Run `pooler auth status` to inspect configured accounts.
2. Run `pooler auth switch --account <ACCOUNT_ID>` to make it the primary active account.
3. Confirm with `pooler auth status`.
```

### Inspect Live Request Traces and Token Usage
```text
Task: Check recent request latency and token usage in Pooler:
1. Open the dashboard directly with `pooler dashboard`.
2. Or query the management API at http://127.0.0.1:18477/requests to summarize token counts, TTFT latency, and recent model failover events.
```
