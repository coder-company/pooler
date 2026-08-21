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
| `/listeners`, `/routes`, `/models` | Active compiled plan and published model view |
| `/health/providers`, `/accounts` | Provider and redacted account health |
| `/quota` | Typed quota windows plus active cooldowns |
| `/metrics`, `/metrics/prometheus` | Bounded route/provider/model token usage and provider-reported cost ticks |
| `/decisions` | Recent redacted routing decisions |
| `/traces` | Bounded redacted runtime traces shared by listeners and reload generations |
| `/audit` | Bounded management mutation audit events |
| `/export` | Versioned redacted diagnostic export |

`/export` is a diagnostic backup, not a credential backup. It intentionally cannot restore tokens or secret references.

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

A reload request notifies the serving CLI's configuration watcher. The watcher rereads and compiles the configured source before publication; invalid candidates leave the active generation unchanged. Listener and management binding changes continue to require a process-level restart.

## Cost records

Pooler does not invent pricing. `cost_in_usd_ticks` is recorded only when a provider response explicitly supplies that integer field. Token usage is normalized from supported JSON and SSE response shapes and attributed to route, provider, and selected model. Observation is bounded and does not retain response content.
