# Agent-Native Setup Guide

This guide provides the complete **Agent-Native** onboarding architecture for Pooler.

When setting up Pooler from any repository or workspace, paste the **Initiation Prompt** below into your AI coding agent (Cursor, Devin, Claude Code, Factory Droid, Codex). The agent will reference the Pooler repository at [https://github.com/coder-company/pooler](https://github.com/coder-company/pooler), interactively ask for your requirements, install Pooler, and configure everything end-to-end.

---

## 1. What the User Pastes to Their Agent (Initiation Prompt)

Copy and paste this prompt into your AI coding agent's chat:

```text
Set up and configure Pooler for this workspace from https://github.com/coder-company/pooler:
1. First, ask me using your interactive question tool:
   - Which coding tool/agent I am using (Cursor, Devin, Factory Droid, Claude Code / Codex, or General SDK/Gateway).
   - What credentials/subscriptions I want to connect (ChatGPT / Codex subscription via device OAuth, Google Gemini OAuth, Anthropic Claude API key, OpenAI API key, xAI Grok, or Custom).
   - Whether I want multi-account pooling with automatic rate-limit failover.
   - What specific models or reasoning settings I want enabled (e.g. gpt-4o, claude-3-7-sonnet, gemini-2.5-pro, o3-mini with high reasoning).
2. Fetch documentation and recipes from https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt or inspect the repository at https://github.com/coder-company/pooler.
3. Install the Pooler binary if not already present:
   `curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash`
4. Initialize the starter workspace using `pooler init --output ./pooler-starter`.
5. Apply the required preset or configuration with secure secret references (env:, file:, or keyring:).
6. Guide me through authentication (such as running `pooler auth login openai --method device-code` for Codex subscriptions or setting environment variables).
7. Run `pooler check` and `pooler preflight` to verify setup without billable inference.
8. Start the server and confirm the exact local base URL for my coding tool.
```

---

## 2. Agent Execution System Prompt (Instructions for Agents)

When an AI agent receives the initiation prompt, it executes the following protocol:

```markdown
### Agent Protocol for Pooler Setup

Repository: https://github.com/coder-company/pooler
Agent Index: https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt

#### Step 1: Interactive User Inquiry (Mandatory)
Before writing any configuration files or running long commands, interactively prompt the user (using structured selection tools like AskQuestion when available):
1. **Target Agent & Preset**:
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

#### Step 2: Binary Installation & Context Discovery
1. If `pooler` is not installed on PATH, install it:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
   ```
2. Inspect the workspace for existing configuration files (`pooler.yaml`, `~/.codex/credentials.json`, environment variables).
3. Read `https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt` to reference preset schemas.

#### Step 3: Initialization & Configuration Generation
1. If no deployment exists, run:
   ```sh
   pooler init --output ./pooler-starter
   ```
2. Generate the appropriate configuration in `config/<agent-name>.yaml` or `pooler-starter/pooler.yaml`.
   - **Cursor Preset**:
     ```yaml
     imports:
       - preset: cursor
         as: cursor-adapter
         with:
           bind: 127.0.0.1:8333
           upstream_url: https://api.openai.com
           reasoning_effort: high
           secret: env:OPENAI_API_KEY
     version: 2
     ```
   - **Devin Preset**:
     ```yaml
     imports:
       - preset: devin
         as: devin-bridge
         with:
           bind: 127.0.0.1:18473
           upstream_url: https://api.openai.com
           secret: env:OPENAI_API_KEY
     version: 2
     ```
   - **Factory Droid Preset**:
     ```yaml
     imports:
       - preset: factory
         as: factory-adapter
         with:
           bind: 127.0.0.1:18474
           upstream_url: https://api.openai.com
           secret: env:OPENAI_API_KEY
     version: 2
     ```
   - **Universal Gateway Preset**:
     ```yaml
     imports:
       - preset: gateway
         as: gateway
         with:
           bind: 127.0.0.1:8400
           upstream_url: https://api.openai.com
           secret: env:POOLER_GATEWAY_KEY
     version: 2
     ```

#### Step 4: Authentication & Credential Storage
- For **ChatGPT / Codex Subscriptions**:
  Run:
  ```sh
  pooler --config pooler-starter/pooler.yaml auth login openai --method device-code
  ```
  Provide the verification URL and user code to the operator, wait for completion, and verify with `pooler auth status --provider openai`.
- For **Importing Existing Codex CLI Credentials**:
  Run:
  ```sh
  pooler --config pooler-starter/pooler.yaml auth import my-codex --profile codex --from-file ~/.codex/credentials.json
  ```
- For **Google Gemini OAuth**:
  Run:
  ```sh
  pooler --config pooler-starter/pooler.yaml auth login google --method oauth
  ```
- For **API Keys**:
  Instruct the user to export the environment variable or save the key in `pooler-starter/provider.key` (`chmod 0600`). Never print or write literal keys to YAML.

#### Step 5: Validation & Preflight
Run:
```sh
pooler check --config <CONFIG_PATH>
pooler --config <CONFIG_PATH> preflight
```
Ensure zero failing checks and verify DNS/TLS reachability.

#### Step 6: Serve & Provide Exact Connection Instructions
1. Instruct the user on running:
   ```sh
   pooler --config <CONFIG_PATH> --credential-key-ref file:<STORE_KEY_PATH> serve
   ```
2. Give clear, copy-paste connection parameters for their chosen tool:
   - **Cursor**: Set Base URL to `http://127.0.0.1:8333` in Cursor Settings → Models → OpenAI API Key / Base URL.
   - **Devin**: Set service endpoint to `http://127.0.0.1:18473`.
   - **Factory Droid**: Set base URL to `http://127.0.0.1:18474`.
   - **Claude Code / AI SDKs**: Set `OPENAI_BASE_URL="http://127.0.0.1:8400/v1"` or `ANTHROPIC_BASE_URL="http://127.0.0.1:8400"`.
3. Provide the management dashboard link: `http://127.0.0.1:18477`.
```

---

## 3. Specific Action Prompts for Agents

### Pool Multiple Subscriptions for Zero-Downtime Rate Limits
```text
Task: Update my Pooler configuration to pool multiple ChatGPT / Codex subscriptions and API keys:
1. Add an account pool named `dev-pool` in pooler.yaml with strategy `fill_first`.
2. Configure automatic retry with `maximum_attempts: 3` on HTTP 429 and 503 errors.
3. Validate the configuration using `pooler check` and render the compiled routes.
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
1. Connect to the management API at http://127.0.0.1:18477 using the management bearer token in pooler-starter/management.token.
2. Query `/usage` and `/requests` endpoints to summarize token counts, TTFT latency, and recent model failover events.
```
