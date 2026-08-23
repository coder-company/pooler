# Secure onboarding and operator clients

Pooler’s onboarding surfaces are thin clients over the compiler, native credential runtime, catalog runtime, and authenticated management API. They do not implement a second routing or provider stack.

## Owner-private bootstrap

Create a new starter directory:

```sh
pooler init --output pooler-starter
```

The command refuses an existing destination and removes a partially created destination if setup fails. It creates an owner-private directory containing:

- `pooler.yaml`, compiler-validated before success;
- `management.token`, a random management bearer token;
- `store.key`, a random encrypted credential-store key;
- `provider.key`, an empty owner-private file for the provider key.

The YAML contains only absolute `file:` references. It never embeds the generated values. On Unix the directory is mode `0700` and files are mode `0600`. Follow the printed commands to populate `provider.key`, check the configuration, and start Pooler with the printed `--credential-key-ref`.

## Dashboard and terminal view

For a local compiled configuration:

```sh
pooler --config pooler-starter/pooler.yaml dashboard
```

The command derives the URL from the loopback management bind and never adds bearer material to it. `--no-open` prints the URL without launching a browser. An explicit `--url` must be HTTPS and cannot contain user information, a query, or a fragment.

The terminal view is intentionally a management API client:

```sh
pooler tui \
  --endpoint http://127.0.0.1:18477 \
  --token-ref file:/absolute/path/to/pooler-starter/management.token
```

Use `--once` for one snapshot. Otherwise the bounded refresh interval reads only `/health`, `/active`, `/health/providers`, `/accounts`, and `/quota`. Cleartext HTTP is accepted only for loopback endpoints; remote endpoints require HTTPS. The token is resolved from `env:`, owner-private `file:`, or `keyring:` and sent only as an Authorization header.

## Non-billable preflight

Run:

```sh
pooler --config pooler-starter/pooler.yaml preflight
```

Preflight performs bounded DNS, native-root TLS, and base-endpoint reachability
checks. When catalog discovery is configured, it also exercises that configured
authenticated discovery path. It sends no inference request and reports
`inference_requests_sent: 0`. Provider-specific authentication placement and
quota endpoints are not probed; quota is reported as unsupported. Preflight
success therefore does not claim quota availability, model output correctness,
or live-provider conformance.

## Typed account creation and OAuth

The dashboard **Accounts** view creates a bounded typed configuration draft. Select the configured upstream, API-key or OAuth identity, and one protected secret-reference kind:

- environment variable name;
- absolute owner-private file path;
- OS keyring service and account.

Literal credentials are not accepted. The endpoint returns only a value-free semantic diff and a one-time confirmation token. Review and commit the draft in **Configuration**; ordinary ETag, compiler, persistence, backup, reload, and rollback protections still apply.

For the documented OpenAI/Codex device flow, **Connect → Start device authorization** brokers the flow through the native runtime. The authenticated browser receives only the provider HTTPS page, short user code, expiry, and status. The device credential and token responses remain server-side; successful tokens are written to the encrypted SQLite credential store. Only one brokered device flow may be active, polling is bounded, and a configuration-generation change prevents persistence. Providers without a documented built-in device flow continue to show the trusted terminal command or explicit-registration guidance; Pooler does not invent clients, scopes, or endpoints.

## Client-specific connection

The setup wizard derives compatible clients from the provider catalog and gives a concrete local address:

- OpenAI-compatible SDKs, Codex, Cursor, and Factory Droid: set the OpenAI base URL to `http://127.0.0.1:8319/v1`;
- Anthropic SDK: set its base URL to `http://127.0.0.1:8319`;
- Gemini SDK: set its base URL to `http://127.0.0.1:8319`;
- Factory protocol: use `http://127.0.0.1:18474`;
- Devin protocol: use `http://127.0.0.1:18473`;
- provider-native clients: use the generated route for the selected provider dialect.

Some clients require a local API-key field. Use a non-secret placeholder only when the client requires one; upstream credentials are selected and applied server-side.

## Bounded provider test console

The setup wizard’s final **Verify running instance** action is the provider test console. It queues the real catalog reload path, waits for the correlated bounded operation, and verifies the active provider/account/model plus matching configuration and catalog generations. Connectivity passes only when a fresh matching discovery observation follows that exact reload. Retained last-good discovery does not count, and the console sends no inference request.

## CLIProxyAPI migration

Inspect a pinned supported CLIProxyAPI Plus configuration without writing output:

```sh
pooler migrate cliproxy /path/to/config.yaml --dry-run
```

The parser is restricted to the supported legacy shape and a 1 MiB input. The report is redacted: legacy API keys and management secrets are never retained or printed. Enabled compatible providers become typed gateway imports with replacement `env:` references. Unsafe or credential-bearing URLs are rejected.

After reviewing the proposal, create a new owner-private file:

```sh
pooler migrate cliproxy /path/to/config.yaml --output migrated.pooler.yaml
```

The destination must not exist. Pooler compiler-validates a temporary sibling before atomically publishing the new file. The source is never modified.
