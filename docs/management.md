# Operational management

Pooler's management listener exposes bounded, redacted runtime state separately from inference traffic. It is disabled unless `management` is configured.

## Security model

- Keep the listener on loopback or an owner-private Unix socket. Remote management remains unsupported until management TLS is available.
- Read endpoints may use the existing loopback policy. Every mutation requires a configured bearer secret, even on loopback.
- Mutation requests accept no body, reject a mismatched `Origin`, and never put the bearer token in a URL.
- Responses use `Cache-Control: no-store`, a restrictive CSP, frame denial, MIME sniffing protection, and no-referrer policy.
- Accounts, traces, audit events, and exports contain metadata only. Credential payloads, secret references, request bodies, and authorization headers are never exported.

Example:

```yaml
management:
  bind: 127.0.0.1:18477
  auth:
    secret: env:POOLER_MANAGEMENT_TOKEN
```

Send the token as `Authorization: Bearer ...`.

## Read endpoints

| Endpoint | Purpose |
| --- | --- |
| `/health` | Process, configuration, store, and active-request status |
| `/setup/options`, `/setup/config`, `/setup/test` | Catalog-derived first-run choices, compiler-validated sidecar generation, and truthful active-runtime checks |
| `/listeners`, `/routes`, `/models` | Active compiled plan and published model view |
| `/health/providers`, `/accounts` | Provider and redacted account health |
| `/quota` | Typed quota windows plus active cooldowns |
| `/metrics`, `/metrics/prometheus` | Bounded route/provider/model token usage and provider-reported cost ticks |
| `/decisions` | Recent redacted routing decisions |
| `/traces` | Bounded redacted runtime traces shared by listeners and reload generations |
| `/audit` | Bounded process-local management mutation audit events |
| `/reloads` | Bounded correlated status for accepted configuration and catalog reload requests |
| `/export` | Versioned redacted diagnostic export |

`/export` is a diagnostic backup, not a credential backup. It intentionally cannot restore tokens or secret references. Audit and trace retention is process-local and resets when the process restarts.

## First-run setup

The dashboard&rsquo;s **Setup** view is a five-stage wizard: provider, account authentication, model, client, and verification. Its choices come from Pooler&rsquo;s built-in provider-login and provider-catalog registries plus the active redacted account and model views. Unsupported provider/client dialect combinations are not offered.

The browser never accepts a provider API key, OAuth client secret, or token. It displays a trusted-terminal `pooler auth login` command and generates YAML containing only documented `env:` references. OAuth methods that require operator-owned registration details are explained but not offered by the wizard. `/setup/config` compiles the generated YAML before returning it. The result is a managed sidecar candidate: download and review it separately, run `pooler check --config pooler.setup.yaml`, then start it with `pooler serve --config pooler.setup.yaml`. Pooler does not rewrite the operator's hand-written YAML or comments.

**Test active connection** requests a catalog-only reload when authenticated mutations are available, waits for the correlated reload result, and then reads `/setup/test`. A connection is reported as `verified` only when the active generation contains the selected provider/account/model and has a successful bounded model-discovery observation. Static configuration or a non-cooling provider alone is reported as `not_probed`; the wizard does not send a potentially billable inference request and does not call that state healthy.

Setup selections may appear in same-origin query strings, but credential values never do. Generated sidecars and downloads use authenticated `fetch` and remain local to the current browser action.

## Mutations

All mutations use `POST`, require configured bearer authentication, and accept an empty body.

```text
POST /accounts/{id}/enable
POST /accounts/{id}/disable
POST /accounts/{id}/switch
POST /accounts/{id}/refresh
POST /accounts/{id}/revoke
POST /models/{public-model-id}/enable
POST /models/{public-model-id}/disable
POST /reload
POST /models/reload
```

Account enable, disable, and switch operations update the live selection registries and persisted credential state. A switch enables the selected account and disables its same-provider siblings atomically in SQLite. OAuth refresh and revoke requests enter a bounded native-runtime command queue and return `202 Accepted`; their eventual result is written to the audit view. Revocation removes only Pooler's local credential payload and disables the account. It does not claim provider-side revocation unless the provider flow explicitly performs it.

Model enablement is a runtime operator control. It is shared across configuration reload generations in the running process, but is not a replacement for a durable catalog override. For durable model policy, declare `catalog.overrides` in configuration and request a reload.

`POST /reload` asks the serving CLI to reread and compile the configured source before publication; invalid candidates leave the active generation unchanged. `POST /models/reload` refreshes only the configured remote model-catalog sources and does not reread configuration or advance the configuration generation. Both return a correlated request ID, and `/reloads` reports bounded `pending`, `succeeded`, `unchanged`, or `failed` outcomes. Requests are bound to the configuration generation that accepted them, so queued work cannot apply to a newer generation. Listener and management binding changes continue to require a process-level restart.

## Cost records

Pooler does not invent pricing. `cost_in_usd_ticks` is recorded only when a provider response explicitly supplies that integer field. Token usage is normalized from supported JSON and SSE response shapes and attributed to route, provider, and selected model. Observation is bounded and does not retain response content.
