# Known-provider integrations

`known_provider` selects a vendored integration contract rather than only a URL.
For example:

```yaml
upstreams:
  groq:
    known_provider: groq
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
pooler providers groq
pooler providers groq --json
```

Most entries use the conservative OpenAI-compatible defaults. Provider-specific
entries override those defaults only where public behavior is known. Current
specializations include Anthropic header/version semantics, Gemini model
parsing and API-key placement, xAI failure classification, and Kimi discovery.
Providers whose endpoint requires an operator-owned resource, region, project,
or hostname (for example Azure OpenAI, Bedrock, and Vertex) remain absent rather
than using fabricated URL templates.

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
