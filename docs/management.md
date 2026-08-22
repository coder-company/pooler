# Operational management

Pooler's management listener exposes bounded, redacted runtime state separately from inference traffic. It is disabled unless `management` is configured.

## Security model

- Keep the listener on loopback or an owner-private Unix socket. Remote management remains unsupported until management TLS is available.
- Read endpoints may use the existing loopback policy. Every mutation requires a configured bearer secret, even on loopback.
- Operational control mutations accept no body. Typed configuration mutations accept only a bounded JSON body with an ETag precondition. Both reject a mismatched `Origin` and never put the bearer token in a URL.
- Responses use `Cache-Control: no-store`, a restrictive CSP, frame denial, MIME sniffing protection, and no-referrer policy.
- Accounts, request history, historical usage, traces, audit events, and exports contain metadata only. Credential payloads, secret references, raw prompts or responses, request bodies, and authorization headers are never exported.

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
| `/config`, `/config/drafts/{id}`, `/config/drafts/{id}/diff` | Active generation and value-free typed-draft metadata or semantic diff |
| `/setup/options`, `/setup/config`, `/setup/test` | Catalog-derived first-run choices, compiler-validated sidecar generation, and truthful active-runtime checks |
| `/listeners`, `/routes`, `/models` | Active compiled plan and published model view |
| `/health/providers`, `/accounts` | Provider and redacted account health |
| `/oauth/device/{request-id}` | Bounded server-side device-flow status and operator prompt; never token material |
| `/quota` | Typed quota windows plus active cooldowns |
| `/metrics`, `/metrics/prometheus` | Bounded process-local compatibility counters |
| `/usage`, `/usage/aggregate` | Paginated retained usage records and bounded multidimensional time-range aggregates |
| `/usage/export`, `/usage/prometheus`, `/usage/otlp` | Bounded redacted JSON, Prometheus text, and OTLP/JSON usage exports |
| `/decisions` | Recent redacted routing decisions |
| `/requests`, `/requests/{id}`, `/requests/{id}/timeline` | Paginated, filterable request summaries and one-ID admission-to-completion timelines |
| `/requests/export` | Bounded versioned export of filtered redacted request history |
| `/traces` | Bounded redacted runtime traces shared by listeners and reload generations |
| `/audit` | Bounded process-local management mutation audit events |
| `/reloads` | Bounded correlated status for accepted configuration and catalog reload requests |
| `/export` | Versioned redacted diagnostic export |

`/export` is a diagnostic backup, not a credential backup. It intentionally cannot restore tokens or secret references. Audit and trace retention is process-local and resets when the process restarts.

## Redacted request explorer

The dashboard **Requests** view correlates admission, route selection and eligibility, every upstream attempt, retry or failover, commitment, first-event/TTFT, semantic degradation, and completion under one logical request ID. The list accepts bounded `route`, `listener`, `provider`, `model`, `status`, `since`, and `until` filters plus an opaque descending `cursor`; the dashboard exposes the common route/provider/status filters and cursor pagination. Detail and timeline lookups validate the identifier and return `404` after retention evicts the request.

Request history contains bounded metadata only: listener and route identifiers, public and upstream model names, provider, a non-secret account pseudonym, attempt count, eligibility outcome, retry reason, commitment, TTFT and latency, status or error class, quota/cooldown effects, semantic-loss decisions, configuration/catalog generations, and only explicitly supplied body hashes. Pooler never derives or stores raw prompts, responses, credentials, authorization headers, or secret references in this history. The normal request path does not enable body hashing.

Memory storage applies deterministic global, per-request, and TTL bounds. Persistent request history is accepted only by the encrypted SQLite store: each event is an authenticated encrypted envelope bound to its row identity, survives restart, and is pruned by the same deterministic retention policy. An unencrypted SQLite store rejects request-history persistence rather than writing metadata in plaintext. `/requests/export` applies the same filters and strict redaction policy, caps the exported record count, and contains no restore material.

## First-run setup

The dashboard&rsquo;s **Setup** view is a five-stage wizard: provider, account authentication, model, client, and activation/verification. Its choices come from Pooler&rsquo;s built-in provider-login and provider-catalog registries plus the active redacted account and model views. Unsupported provider/client dialect combinations are not offered. Google browser OAuth is intentionally marked as requiring explicit configuration because Pooler cannot safely invent operator-owned OAuth registration details.

The browser never accepts a provider API key, OAuth client secret, or token. `/setup/config` compiles the generated YAML before returning it. The result is a managed sidecar candidate; Pooler does not rewrite the operator's hand-written YAML or comments. Complete setup in this order:

1. Generate and download `pooler.setup.yaml`.
2. Set its referenced environment secrets, including `POOLER_STORE_KEY` and `POOLER_MANAGEMENT_TOKEN`.
3. Run `pooler check --config pooler.setup.yaml`.
4. Run `pooler --config pooler.setup.yaml --credential-key-ref env:POOLER_STORE_KEY auth login <provider> --account <account> --method <method>`.
5. Start the generated configuration with `pooler --config pooler.setup.yaml --credential-key-ref env:POOLER_STORE_KEY serve`.
6. Reopen or reconnect the dashboard and verify that running instance.

**Verify running instance** is the bounded provider test console. It requests a catalog-only reload, requires that correlated request to succeed, and then reads `/setup/test` with the reload request ID. A connection is reported as `verified` only when the active provider/account/model match, the configuration and catalog generations match the completed reload, and a matching discovery observation is newer than the reload request. Retained last-good discovery is never fresh verification. The console does not send a potentially billable inference request. Bootstrap, dashboard, preflight, migration, TUI, and client instructions are documented in [secure onboarding](onboarding.md).

Setup selections may appear in same-origin query strings, but credential values never do. Generated sidecars and downloads use authenticated `fetch` and remain local to the current browser action.

## Connecting configured accounts

The **Accounts** view combines the redacted `/accounts` state with the catalog-derived `/setup/options` authentication facts. Its typed account form sends only an account ID, configured upstream, authentication kind, and structured `env`, `file`, or `keyring` reference metadata to `/config/accounts/draft`. Literal secret values and unrestricted YAML are rejected. The server creates and validates an ordinary configuration draft and returns only its ETag, value-free semantic diff, and one-time confirmation token; activation still requires explicit commit from **Configuration**.

**Connect** shows an exact `pooler auth login <configured-upstream> --profile <provider-profile> --account <account-id>` command for supported methods. For the documented OpenAI/Codex device flow it can instead queue `POST /accounts/{id}/oauth-device`: the native runtime starts and polls the provider flow, the browser receives only the provider HTTPS page, short user code, expiry, and status, and token responses are persisted directly to encrypted SQLite. Only one brokered flow is active at a time, polling is bounded, and a generation change prevents persistence. Methods requiring operator-owned registration remain terminal-only and are explained instead of guessed.

API keys stay in environment variables or another protected reference, while OAuth device credentials and tokens remain server-side. No bearer, code-exchange response, or token is placed in dashboard URLs, API responses, logs, exports, or browser storage. **Check redacted account status** performs authenticated reads only; it does not send inference traffic and an `available` local credential is not labelled as verified provider connectivity.

## Mutations

The operational controls below use body-free `POST` requests and require configured bearer authentication. Typed durable configuration additionally uses bounded JSON `PATCH` and `POST` operations with `If-Match`; see [typed durable configuration](configuration-management.md).

```text
POST /accounts/{id}/enable
POST /accounts/{id}/disable
POST /accounts/{id}/switch
POST /accounts/{id}/refresh
POST /accounts/{id}/revoke
POST /accounts/{id}/oauth-device
POST /models/{public-model-id}/enable
POST /models/{public-model-id}/disable
POST /reload
POST /models/reload
```

Account enable, disable, and switch operations update the live selection registries and persisted credential state. A switch enables the selected account and disables its same-provider siblings atomically in SQLite. OAuth refresh, revoke, and documented device-login requests enter the bounded native-runtime command queue and return `202 Accepted`; their eventual result is written to the audit view. Device polling runs independently so it cannot starve refresh, revoke, or reload controls. Revocation removes only Pooler's local credential payload and disables the account. It does not claim provider-side revocation unless the provider flow explicitly performs it.

Model enablement is a runtime operator control. It is shared across configuration reload generations in the running process, but is not a replacement for a durable catalog override. For durable model policy, declare `catalog.overrides` in configuration and request a reload.

`POST /reload` asks the serving CLI to reread and compile the configured source before publication; invalid candidates leave the active generation unchanged. `POST /models/reload` refreshes only the configured remote model-catalog sources and does not reread configuration or advance the configuration generation. Both return a correlated request ID, and `/reloads` reports bounded `pending`, `succeeded`, `unchanged`, or `failed` outcomes. Requests are bound to the configuration generation that accepted them, so queued work cannot apply to a newer generation. Listener and management binding changes continue to require a process-level restart.

## Typed durable configuration

The dashboard's **Configuration** view creates an expiring server-side draft, applies section-scoped operations, compiles the whole candidate, shows a value-free semantic diff, and requires explicit confirmation before persistence. Pooler writes an owner-private generated sidecar rather than modifying hand-authored YAML. Atomic persistence, backup, reload correlation, failure restoration, and explicit rollback are documented in [typed durable configuration](configuration-management.md).

## Historical usage ledger

Each completed request appends one bounded metadata-only usage record. The record contains explicitly reported input, output, reasoning, and cache tokens; explicitly reported image, audio, and video units; route, provider, public and upstream model, and non-secret account pseudonym; latency and TTFT; result class and service tier; configuration and catalog generation; and cost provenance. JSON, SSE, and unfragmented upstream WebSocket JSON events use the same bounded usage normalizer. Pooler does not retain response or frame content after extracting these fields.

Memory and SQLite stores apply an independent usage-record count and TTL policy; request-history retention does not control usage retention. Persistent usage is accepted only by encrypted SQLite. Every record is an authenticated encrypted envelope bound to its row identity, survives restart, and fails closed if modified. Unencrypted SQLite rejects usage persistence. The list/export paths cap records, aggregation caps both grouping dimensions and output series, and all management responses pass through strict redaction.

`/usage` accepts descending `cursor` pagination plus `since`, `until`, `route`, `provider`, `model`, `account`, `result_class`, and `service_tier` filters. `/usage/aggregate`, `/usage/prometheus`, and `/usage/otlp` accept the same filters and up to six comma-separated `group_by` dimensions from `route`, `provider`, `public_model`, `upstream_model`, `account`, `result_class`, `service_tier`, `cost_provenance`, `price_book_version`, `configuration_generation`, and `catalog_generation`. Aggregation returns at most 256 series and reports the number of records dropped by that cardinality bound. The dashboard **Usage** view offers one-hour, 24-hour, seven-day, 30-day, and all-retained ranges and a bounded JSON export.

### Cost provenance and operator price books

Pooler never invents prices. A provider-supplied `cost_in_usd_ticks` is stored as `provider_reported` and always takes precedence. Without a provider cost, provenance remains `unknown` unless the active configuration has an exact provider/upstream-model match in an explicit versioned `usage_price_book`. Such a match stores `operator_estimated`, its price-book version, and the deterministic estimate. Token rates are integer USD ticks per million reported tokens and round down after each term; media rates are integer USD ticks per explicitly reported unit. Omitted rates do not contribute. Operators must use one deployment-wide fixed-decimal tick scale for provider and price-book values.

```yaml
usage_price_book:
  version: operator-2026-08-22
  entries:
    - provider: openai
      model: gpt-example-2026
      input_per_million_usd_ticks: 0 # replace with an operator-sourced rate
      output_per_million_usd_ticks: 0 # replace with an operator-sourced rate
```

The example deliberately contains no real price. The compiler rejects an empty version, duplicate provider/model entries, unknown upstream IDs, entries with no rates, and unknown fields. A typed configuration draft may replace the complete `usage_price_book` section; semantic diffs reveal only that the section changed, never its values.
