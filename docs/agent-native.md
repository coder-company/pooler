# Agent-native prompts cookbook

Agent-native documentation empowers AI coding agents (such as Cursor, Devin, Factory Droid, Claude Code, and Codex) to autonomously bootstrap, configure, authenticate, and manage Pooler.

Instead of manually crafting YAML or running terminal sequences, pass any of the task prompts below to your coding agent.

---

## 1. Subscriptions & OAuth authentication prompts

### Connect ChatGPT / Codex subscription via device flow
```text
Task: Authenticate an OpenAI / ChatGPT / Codex subscription account in Pooler.
1. Run the device code login command:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth login openai --method device-code
2. Display the official verification URL and the one-time user code to the operator.
3. Once authorized, verify the stored credential with:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth status --provider openai
4. Report that the subscription token is active in the encrypted SQLite store.
```

### Import local Codex CLI credentials
```text
Task: Import local OpenAI Codex CLI subscription tokens into Pooler.
1. Check that ~/.codex/credentials.json exists and contains valid subscription tokens.
2. Import the credentials into Pooler's encrypted store:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth import codex-sub --profile codex --from-file ~/.codex/credentials.json
3. Verify the imported account status:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth status --provider codex
```

### Connect Google Gemini via browser PKCE OAuth
```text
Task: Authenticate a Google Gemini subscription or OAuth account.
1. Run browser PKCE login:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth login google --method oauth
2. If non-interactive, print the local loopback callback redirect URL.
3. Confirm that the refresh token is stored securely using `pooler auth status --provider google`.
```

### Connect Anthropic, xAI, or custom API keys
```text
Task: Configure an Anthropic Claude or xAI Grok provider key using safe secret references.
1. Never put the literal API key in YAML or CLI arguments.
2. In pooler.yaml under upstreams, set the secret reference:
   upstreams:
     anthropic-upstream:
       known_provider: anthropic
       auth:
         secret: env:ANTHROPIC_API_KEY
3. Verify the configuration with `pooler check --config pooler.yaml`.
4. Run `pooler --config pooler.yaml preflight` to confirm connectivity without billable inference.
```

---

## 2. Multi-account pooling & failover prompts

### Pool multiple Codex subscriptions + API keys with automatic failover
```text
Task: Configure multi-account pooling across 2 Codex subscriptions and 1 backup API key.
1. In pooler.yaml, configure the account pool with the fill_first strategy:
   account_pools:
     main-pool:
       provider: openai
       accounts: [codex-sub-1, codex-sub-2, openai-api-backup]
   policies:
     openai-policy:
       selection:
         strategy: fill_first
       retry:
         maximum_attempts: 3
         statuses: [429, 500, 503]
         before_commit_only: true
2. Validate with `pooler check --config pooler.yaml`.
3. Check route bindings with `pooler routes --config pooler.yaml`.
```

---

## 3. Coding agent adapter presets

### Configure Cursor IDE adapter
```text
Task: Configure Pooler for Cursor on port 8333 with reasoning parameter injection.
1. Create config/cursor.yaml with:
   imports:
     - preset: cursor
       as: cursor-adapter
       with:
         bind: 127.0.0.1:8333
         reasoning_effort: high
         model_prefix: gpt-
         upstream_url: https://api.openai.com
         secret: env:OPENAI_API_KEY
   version: 2
2. Validate: `pooler check --config config/cursor.yaml`.
3. Inform the operator to set Cursor's OpenAI Base URL to http://127.0.0.1:8333.
```

### Configure Devin ConnectRPC bridge
```text
Task: Bridge Devin protobuf ConnectRPC requests to upstream OpenAI / Codex subscriptions.
1. Create config/devin.yaml:
   imports:
     - preset: devin
       as: devin-bridge
       with:
         bind: 127.0.0.1:18473
         upstream_url: https://api.openai.com
         secret: env:OPENAI_API_KEY
   version: 2
2. Validate with `pooler check --config config/devin.yaml`.
3. Verify compiled routes with `pooler --config config/devin.yaml routes`.
4. Provide the Devin endpoint address http://127.0.0.1:18473.
```

### Configure Factory Droid adapter
```text
Task: Configure Pooler to translate Factory Droid language-model endpoints.
1. Create config/factory.yaml:
   imports:
     - preset: factory
       as: factory-adapter
       with:
         bind: 127.0.0.1:18474
         upstream_url: https://api.openai.com
         secret: env:OPENAI_API_KEY
   version: 2
2. Validate with `pooler check --config config/factory.yaml`.
3. Point Factory Droid to http://127.0.0.1:18474.
```

### Configure universal multi-provider gateway
```text
Task: Mount a universal gateway on port 8400 supporting OpenAI, Anthropic, and Gemini SDKs.
1. Create config/gateway.yaml:
   imports:
     - preset: gateway
       as: gateway
       with:
         bind: 127.0.0.1:8400
         upstream_url: https://api.openai.com
         websocket_url: wss://api.openai.com
         secret: env:POOLER_GATEWAY_KEY
   version: 2
2. Validate with `pooler check --config config/gateway.yaml`.
3. Run non-billable preflight: `pooler --config config/gateway.yaml preflight`.
```

---

## 4. Diagnostics, migration & operations

### Run system diagnostics & health checks
```text
Task: Run complete diagnostics on the Pooler environment.
1. Run `pooler doctor --config pooler.yaml` to verify port availability, store encryption keys, and file permissions.
2. Run `pooler --config pooler.yaml preflight` to verify upstream TLS, DNS, and reachability.
3. Report any warnings or failing checks.
```

### Migrate legacy CLIProxyAPI configuration
```text
Task: Convert a legacy CLIProxyAPI configuration into a native Pooler configuration.
1. Run a dry-run migration:
   pooler migrate cliproxy /path/to/cliproxy.yaml --dry-run
2. Verify that no raw credentials are exposed in the output.
3. Save the migrated configuration to config/migrated.pooler.yaml:
   pooler migrate cliproxy /path/to/cliproxy.yaml --output config/migrated.pooler.yaml
4. Verify with `pooler check --config config/migrated.pooler.yaml`.
```
