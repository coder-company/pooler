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

Kimi still needs an operator-owned registration:

```console
pooler --credential-key-ref env:POOLER_STORE_KEY auth login kimi \
  --method device-code \
  --device-authorization-endpoint https://auth.kimi.com/device
```

Codex browser and device login use the official Codex CLI installed-app client
and endpoints, so `pooler auth login openai` and
`pooler auth login openai --method device-code` talk to OpenAI directly. Kimi
device login still requires a complete operator-owned client registration.
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

## Status and revocation

`pooler auth status` shows redacted credential metadata only. A built-in alias
filters its canonical profile, so `status gemini` also matches credentials
stored for `google`. `pooler auth revoke <configured-upstream>` removes the
local credential and uses a configured revocation endpoint when encrypted token
access is available.

OAuth override values, callback codes, state, tokens, and API keys are omitted
from command debug output and errors. Client IDs, scopes, endpoint URLs, and
aggregate input all have hard size limits before any network or store access.
