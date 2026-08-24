# Known-provider integrations

This build ships endpoint integrations for **172 known providers**. `known_provider`
selects a vendored integration contract rather than only a URL. For example:

```yaml
upstreams:
  groq:
    known_provider: groq
```

List or search the shipped table without reading credentials:

```console
pooler providers
pooler providers --search groq
```

Pooler supplies the provider base URL, a protected reference to the provider's
preferred credential environment variable when one is documented, authentication
provider binding, model-discovery parser and path, request dialect and
capability hints, quota-classifier family, endpoint families, model aliases and
exclusions, and required non-secret headers or query parameters.

The credential value is never copied into configuration or the provider table.
The integration records only an `env:` reference. An explicit `auth`, `url`,
`native`, `query`, or catalog declaration remains the operator's override.
Explicit OAuth configuration never inherits API-key authentication.

When no `catalog` section is present, each known-provider upstream with a
documented parser becomes a bounded model-discovery source automatically. An
explicit `catalog` section replaces this automatic source list so operators can
control accounts, prefixes, aliases, filters, bounds, and refresh behavior.

Inspect the effective vendored facts without reading credentials:

```console
pooler providers --search groq
pooler providers --search groq --json
```

Most entries use the conservative OpenAI-compatible defaults. Provider-specific
entries override those defaults only where public behavior is known. Current
specializations include Anthropic header/version semantics, Gemini model
parsing and API-key placement, xAI failure classification, and Kimi discovery.
Providers whose endpoint requires an operator-owned resource, region, project,
or hostname (for example Azure OpenAI, Bedrock, and Vertex) remain absent rather
than using fabricated URL templates. Configure those as custom upstreams.

## Custom endpoints

The known list is a convenience, not a boundary. Any other HTTP or WebSocket
endpoint works as a custom upstream: declare an explicit `url` and state how the
credential is presented.

```yaml
upstreams:
  my-private-llm:
    url: https://llm.internal.example.com
    auth:
      kind: header
      header: x-internal-key
      secret: env:MY_PRIVATE_LLM_KEY
```

Accepted `auth.kind` values are `bearer`, `bearer_secret`, `x_api_key`,
`x_goog_api_key`, and `header`. Use `kind: header` with a `header` name for a
provider that expects its key in a non-standard header, and `value_prefix` when
the header value carries one. The field is `header`, not `header_name`.

A custom upstream is a first-class upstream. It participates in account pooling,
retry and failover policy, quota cooldowns, usage and cost accounting, and the
dashboard exactly like a known provider. What it does not inherit is the
vendored contract: Pooler cannot supply a discovery parser, model aliases, or a
quota classifier it has never seen, so declare a `catalog` source and any
`overrides` the deployment needs.

An explicit `auth`, `url`, `native`, `query`, or `catalog` declaration on a
`known_provider` upstream is also an override, so a self-hosted deployment of a
known provider can reuse its dialect while replacing the base URL.

## Per-model profiles

Pooler also vendors a deterministic, bounded projection of `https://models.dev/api.json`.
Each observed model profile can carry:

- reasoning support, documented effort values, toggle/budget controls, and the
  interleaved reasoning field name;
- tool, attachment, and structured-output support;
- input/output text, image, audio, PDF, and video modalities;
- context, input-token, and output-token limits; and
- request-dialect facts such as rejected `temperature`.

Unknown and unsupported are distinct. Missing facts preserve the existing request
behavior, while an explicit unsupported fact removes the corresponding routing
capability and is enforced before transport. Output ceilings are rejected under
`loss_policy: reject` and clamped only when degradation is explicitly allowed.
Provider integration facts add documented endpoint families, streaming support,
and protocol token-limit field semantics without deriving them from provider-name
conditionals.

Refresh the pinned snapshot with `pooler catalog refresh`; verify it without
writing with `pooler catalog refresh --check`. The snapshot records its source
SHA-256 and contains no provider credentials.

Operators remain authoritative when provider documentation or deployment-specific
behavior is more precise than the vendored source:

```yaml
catalog:
  sources: [{id: private.primary, provider: private, parser: open_ai}]
  overrides:
    - model: private/reasoner
      profile:
        reasoning: supported
        reasoning_efforts: {low: true, high: true}
        tools: unsupported
        context_limit: 131072
        output_limit: 8192
        streaming: unsupported
        token_limit_field: max_completion_tokens
        request_transform: open_ai_chat
        endpoint_variants: {chat_completions: true}
```

A declared `capabilities` replacement also updates the corresponding reasoning,
tool, structured-output, streaming, and attachment support facts. A narrower
`dialect` replacement wins over the dialect nested in `profile`.
