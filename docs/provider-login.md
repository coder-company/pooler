# Provider login

Pooler keeps provider login policy separate from OAuth mechanics. The built-in
registry currently describes OpenAI/Codex, Anthropic/Claude, Google/Gemini,
xAI/Grok, and Kimi/Moonshot. Inspect the exact support matrix without reading
configuration or credentials:

```console
pooler auth providers
pooler auth providers gemini
```

Profile names and aliases are case-insensitive. `pooler auth login gemini`
selects the Google profile and, when the configuration contains an upstream
named `google`, resolves that canonical upstream. A differently named upstream
can select the profile explicitly:

```console
pooler auth login work-google --profile gemini
```

Without `--profile`, an upstream name that does not match a built-in ID or
alias retains Pooler's existing generic configured-OAuth behavior.

## Login methods

Browser authorization-code login remains the default and always uses a
loopback callback, state validation, and S256 PKCE:

```console
pooler --credential-key-ref env:POOLER_STORE_KEY auth login google
```

Device authorization is explicit. Codex uses the official CLI device flow
and does not need extra endpoint flags:

```console
pooler --credential-key-ref env:POOLER_STORE_KEY auth login openai \
  --method device-code
```

Kimi Coding still needs a complete operator-owned registration; Pooler does
not ship or guess a proprietary client ID or scopes:

```console
pooler --credential-key-ref env:POOLER_STORE_KEY auth login kimi \
  --method device-code \
  --client-id "$KIMI_CLIENT_ID" \
  --scope "$KIMI_REGISTERED_SCOPE" \
  --device-authorization-endpoint https://auth.kimi.com/api/oauth/device_authorization \
  --token-endpoint https://auth.kimi.com/api/oauth/token
```

Codex browser and device login use the official Codex CLI installed-app client
and endpoints, so `pooler auth login openai` and
`pooler auth login openai --method device-code` talk to OpenAI directly. Kimi
Coding device login remains pinned compatibility and requires a complete
operator-owned client registration. Its stored OAuth access token is
materialized as a refreshable bearer credential only for a configured native
`kind: kimi` upstream. This subscription identity is distinct from Kimi Open
Platform (`api.moonshot.ai`) API-key accounts; Pooler never silently substitutes
one identity class for the other.
A login invocation may replace Codex defaults with `--client-id`,
repeated `--scope`, `--authorization-endpoint`, `--token-endpoint`,
`--device-authorization-endpoint`, `--revocation-endpoint`, and
`--identity-endpoint`. `--request-encoding json` is available only when the
registered provider client requires JSON token requests.

Built-in profiles enforce provider DNS allowlists in `pooler-auth`; endpoint
overrides cannot redirect OAuth traffic to private, loopback, link-local,
literal-IP, or unrelated hosts. This cannot be disabled. An unprofiled custom
provider may use endpoints already declared in configuration. Replacing those
hosts on the command line additionally requires the conspicuous
`--dangerously-allow-custom-oauth-endpoints` boundary.

## API keys

Pooler never accepts an API key as a command-line value. Ask for provider-safe
configuration guidance instead:

```console
pooler auth login anthropic --method api-key
```

Then configure a protected secret reference, for example:

```yaml
upstreams:
  anthropic:
    url: https://api.anthropic.com
    auth:
      secret: env:ANTHROPIC_API_KEY
```

`env:`, owner-private `file:`, and `keyring:` references keep the value out of
configuration output and process arguments. Anthropic subscription OAuth and
xAI OAuth are intentionally unsupported for third-party Pooler clients. Even a
complete set of endpoint overrides fails before configuration, credential-store,
or network access; use the documented API-key flow instead.

## AI Studio identities

Google AI Studio uses a Gemini API key associated with a Google Cloud project.
Configure it as a protected secret reference; Pooler injects only the selected
upstream's key as `x-goog-api-key` and strips caller-supplied
`Authorization`, `x-api-key`, and `x-goog-api-key` values first:

```yaml
upstreams:
  google:
    known_provider: google
    auth:
      secret: env:GEMINI_API_KEY
```

The native Gemini surface preserves the documented `/v1beta/models`,
`generateContent`, `streamGenerateContent`, `countTokens`, and Interactions
wire shapes. AI Studio `RESOURCE_EXHAUSTED` and `QUOTA_EXCEEDED` evidence is
classified at project scope without claiming that one credential caused the
project-wide exhaustion. An AI Studio API-key account is not a Vertex OAuth or
service-account identity, and Pooler never moves credentials between those
providers during selection or retry.

## Vertex identities and resource addressing

Vertex project endpoints use Google OAuth access tokens, not AI Studio API keys.
Declare the project and location explicitly so Pooler can construct the documented
publisher-model resource path without deriving tenant identity from a caller URL:

```yaml
upstreams:
  vertex:
    url: https://us-central1-aiplatform.googleapis.com
    native:
      kind: vertex
      project: my-production-project
      location: us-central1
      publisher: google
    oauth:
      authorization_endpoint: https://accounts.google.com/o/oauth2/v2/auth
      token_endpoint: https://oauth2.googleapis.com/token
      client_id: operator-registered-google-client-id
      scopes: [https://www.googleapis.com/auth/cloud-platform]
accounts:
  vertex-user:
    provider: vertex
    auth_kind: oauth
```

The OAuth client is operator-owned. Pooler stores and refreshes its access token
and injects it as a sensitive `Authorization: Bearer` value after stripping
caller-supplied Google and generic credential headers. Pooler does not mint
service-account JWT assertions or parse undocumented credential exports. An
operator using workload identity or a service account may instead rotate a
short-lived access token in an owner-private `file:` or `keyring:` secret
reference; Pooler rereads that protected reference when authorizing requests.
Project/location OAuth accounts, externally minted service-account tokens, and
AI Studio API-key accounts remain distinct account identities and are never
substituted for one another.

## Explicit nonstandard OpenAI-compatible providers

A vendor that resembles OpenAI but changes endpoint paths or credential
placement must be configured explicitly. Pooler does not infer compatibility
from a hostname or forward every OpenAI operation automatically. Declare the
nonstandard header, prefix, allowed routes, and public-to-upstream model mapping:

```yaml
upstreams:
  compatible:
    url: https://vendor.example/api
    native: {kind: compatible}
    auth:
      kind: header
      header: x-provider-token
      value_prefix: 'Token '
      secret: env:VENDOR_API_KEY
models:
  - id: public-model
    targets:
      - provider: compatible
        upstream_model: vendor-model
        capabilities: [text]
routes:
  - id: compatible-chat
    listen: gateway
    match: {method: POST, path: /v1/chat/completions, content_types: [application/json]}
    limits: {max_request_body_bytes: 1048576, max_frame_bytes: 1048576}
    ingress: {mode: patch, inspectors: [inspect.openai.model]}
    target:
      endpoint_family: chat_completions
      provider: compatible
      path: /vendor/v2/generate
      model_from: request.model
    response: {mode: opaque}
```

Only declared operations are reachable. Pooler strips standard caller
credential headers, overwrites the configured custom credential header with the
selected account's sensitive value, rewrites only the selected model field, and
preserves unknown vendor request and response fields. Generic compatible OAuth
or subscription accounts fail closed unless the operator supplies a documented
provider-specific integration; they never borrow an API key from another
account or provider.

## Antigravity pinned compatibility identity

Antigravity is not a public provider contract. Pooler exposes only an explicit,
pinned compatibility mode based on CLIProxyAPI revision
`2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`; it is never enabled by a Google
or Gemini alias. Pooler does not copy the reference client's embedded OAuth
registration, guess scopes, or claim that those internal endpoints are stable.

An owner who is authorized to use that surface must import and rotate their own
short-lived access token through an owner-private `file:` or `keyring:` reference
and explicitly declare `native.kind: antigravity`. Internal routes are also
operator-declared rather than silently added to the universal gateway:

```yaml
upstreams:
  antigravity:
    url: https://cloudcode-pa.googleapis.com
    native: {kind: antigravity}
    auth:
      secret: file:/run/user/1000/pooler/antigravity-access-token
routes:
  - id: antigravity-generate
    listen: gateway
    match:
      methods: [POST]
      path: /v1internal:generateContent
      content_types: [application/json]
    limits: {max_request_body_bytes: 1048576, max_frame_bytes: 1048576}
    ingress: {mode: opaque}
    target: {endpoint_family: generate_content, provider: antigravity}
    response: {mode: opaque}
```

Pooler preserves the pinned internal request envelope and caller-selected
compatibility user agent; it does not synthesize proprietary profile metadata.
It strips downstream credential headers before inserting the selected bearer.
Antigravity identities cannot be selected for AI Studio, Vertex, or another
provider, and its model hints, credit evidence, and Google RPC errors are parsed
with bounded compatibility-only codecs.

## Named accounts and lifecycle

Account names come from `accounts` in the Pooler configuration. Login and import
never create configuration implicitly: select a configured account with
`pooler auth login <provider> --account <account>`. When a provider has more
than one OAuth account, `--account` is required. Owner-private file import is
currently limited to the documented OpenAI/Codex credential shape:

```console
pooler --credential-key-ref env:POOLER_STORE_KEY auth import work-openai \
  --profile openai --from-file ~/.config/private/openai.json
```

Other providers use documented browser/device login or protected API-key secret
references; Pooler does not guess proprietary credential file formats.

`pooler auth status` shows redacted credential metadata, including whether a
stored OAuth token expiry is valid, expired, or unknown. A built-in alias filters
its canonical profile, so `status gemini` also matches credentials stored for
`google`.

Use account IDs for deterministic lifecycle operations:

```console
pooler --credential-key-ref env:POOLER_STORE_KEY auth refresh work-openai
pooler auth disable personal-openai
pooler auth enable personal-openai
pooler auth switch work-openai
pooler --credential-key-ref env:POOLER_STORE_KEY auth revoke work-openai
```

`refresh` rotates one OAuth account with the persisted generation compare-and-
swap contract. `switch` enables the named account and disables sibling accounts
for the same configured provider; it does not modify the configuration or move
credentials between providers. `revoke` accepts an account ID, or a provider
only when exactly one matching account exists. It calls the configured
revocation endpoint when encrypted token access is available, then removes local
credential state. API-key values remain in their external `env:`, `file:`, or
`keyring:` owner and are never copied into the credential database.

OAuth override values, callback codes, state, tokens, and API keys are omitted
from command debug output and errors. Client IDs, scopes, endpoint URLs, and
aggregate input all have hard size limits before any network or store access.
