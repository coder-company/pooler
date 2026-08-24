# Agent-native guide

Agent-native documentation provides actionable prompts that AI coding agents (such as Cursor, Devin, Factory Droid, Claude Code, and Codex) can execute to configure, test, and manage Pooler deployments autonomously.

Instead of manually executing setup steps, copy any of the task prompts below and give it to your coding agent.

---

## Agent prompt recipes

### Bootstrap starter deployment

```text
Initialize and verify a new Pooler starter deployment:
1. Run `pooler init --output ./pooler-starter` to create an owner-private setup directory.
2. Verify that the files `pooler.yaml`, `management.token`, `store.key`, and `provider.key` exist in ./pooler-starter.
3. Check the configuration with `pooler check --config ./pooler-starter/pooler.yaml`.
4. Run preflight network checks with `pooler --config ./pooler-starter/pooler.yaml preflight`.
5. Report the generated management token and command to start Pooler.
```

### Configure Cursor adapter

```text
Configure Pooler as a dedicated proxy for Cursor IDE on port 8333:
1. Create a configuration file named `config/cursor.yaml` with the following contents:
   imports:
     - preset: cursor
       as: cursor-high
       with:
         bind: 127.0.0.1:8333
         reasoning_effort: high
         model_prefix: gpt-
         upstream_url: https://api.openai.com
         secret: env:OPENAI_API_KEY
   version: 2
2. Validate the configuration: `pooler check --config config/cursor.yaml`.
3. Render the expanded configuration: `pooler --config config/cursor.yaml config render`.
4. Instruct the user to set their Cursor OpenAI Base URL to `http://127.0.0.1:8333`.
```

### Configure Devin ConnectRPC adapter

```text
Set up Pooler to translate Devin ConnectRPC protocol requests to OpenAI chat completions:
1. Create `config/devin.yaml` importing the built-in devin preset:
   imports:
     - preset: devin
       as: devin-bridge
       with:
         bind: 127.0.0.1:18473
         upstream_url: https://api.openai.com
         secret: env:OPENAI_API_KEY
   version: 2
2. Verify the configuration: `pooler check --config config/devin.yaml`.
3. Inspect compiled route precedence: `pooler --config config/devin.yaml routes`.
4. Provide the Devin endpoint address `http://127.0.0.1:18473` to the operator.
```

### Configure Factory Droid adapter

```text
Set up Pooler to translate Factory Droid language-model requests:
1. Create `config/factory.yaml`:
   imports:
     - preset: factory
       as: factory-bridge
       with:
         bind: 127.0.0.1:18474
         upstream_url: https://api.openai.com
         secret: env:OPENAI_API_KEY
   version: 2
2. Validate the configuration using `pooler check --config config/factory.yaml`.
3. Verify that `/v3/ai/language-model` and `/v4/ai/language-model` routes are compiled.
4. Point Factory Droid to `http://127.0.0.1:18474`.
```

### Configure multi-provider gateway

```text
Create a unified multi-provider gateway configuration on port 8400:
1. Create `config/gateway.yaml` importing the gateway preset:
   imports:
     - preset: gateway
       as: gateway
       with:
         bind: 127.0.0.1:8400
         upstream_url: https://api.openai.com
         websocket_url: wss://api.openai.com
         secret: env:POOLER_GATEWAY_KEY
   version: 2
2. Validate the configuration: `pooler check --config config/gateway.yaml`.
3. Run preflight to verify endpoint connectivity: `pooler --config config/gateway.yaml preflight`.
4. Output the active listening endpoints and available routes.
```

### Authenticate provider account via device flow

```text
Authenticate an OpenAI / Codex account using the device authorization flow:
1. Ensure POOLER_STORE_KEY is set or provide an existing store.key reference.
2. Run the device login command:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth login openai --method device-code
3. Display the provider authorization URL and user code to the operator.
4. Wait for the flow to complete and verify the credential status using:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth status --provider openai
```

### Authenticate provider account via browser PKCE

```text
Authenticate a Google Gemini provider account using the loopback browser flow:
1. Ensure the master key is referenced: `--credential-key-ref env:POOLER_STORE_KEY`.
2. Start the login process:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth login google --method oauth
3. If non-interactive, report the local callback URL for the browser redirect.
4. Verify the stored credential status with:
   pooler --credential-key-ref env:POOLER_STORE_KEY auth status --provider google
```

### Migrate from CLIProxyAPI

```text
Migrate a legacy CLIProxyAPI configuration to a validated Pooler configuration:
1. Perform a dry-run migration to inspect the translated configuration:
   pooler migrate cliproxy /path/to/cliproxy.yaml --dry-run
2. Verify that no secrets or API keys are printed in plaintext.
3. Write the validated Pooler configuration to a new file:
   pooler migrate cliproxy /path/to/cliproxy.yaml --output config/migrated.pooler.yaml
4. Verify the output with `pooler check --config config/migrated.pooler.yaml`.
```

### Run system diagnostics

```text
Run comprehensive health checks on the Pooler installation:
1. Execute `pooler doctor --config pooler.yaml` to check file permissions, store integrity, and listener binds.
2. Execute `pooler --config pooler.yaml preflight` to check DNS, TLS, and upstream reachability without billable inference.
3. Report any failing checks and required remediation steps.
```

---

## Agent execution contract

When executing any prompt recipe:

1. **Safety first**: Never embed literal API keys, bearer tokens, or secrets in configuration files or command arguments. Use `env:`, `file:`, or `keyring:` references.
2. **Deterministic validation**: Always run `pooler check --config <PATH>` before attempting to start a server or commit changes.
3. **No file overwriting**: When generating new starter deployments or migrated configurations, never overwrite an existing file. Use distinct output paths.
4. **Verification**: Confirm network listening ports with `pooler doctor` or `pooler routes` before notifying the user of task completion.
