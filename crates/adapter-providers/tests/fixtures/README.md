# Provider contract fixtures

`provider-contracts.json` is synthetic and credential-free. Its field shapes are
reduced from these source contracts; it is not a claim of live-provider
conformance:

- Kimi Open Platform API overview and model-list reference:
  <https://platform.kimi.ai/docs/api/overview> and
  <https://platform.kimi.ai/docs/api/list-models>
- Vertex AI quickstart, inference errors, and throughput quota documentation:
  <https://cloud.google.com/vertex-ai/generative-ai/docs/start/quickstart>,
  <https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/api-errors>, and
  <https://cloud.google.com/vertex-ai/generative-ai/docs/resources/throughput-quota>
- Google AI Studio Gemini API keys and project-level rate limits:
  <https://ai.google.dev/gemini-api/docs/api-key> and
  <https://ai.google.dev/gemini-api/docs/rate-limits>
- OpenAI authentication and model-list baseline:
  <https://developers.openai.com/api/reference/overview> and
  <https://developers.openai.com/api/reference/resources/models>
- Kimi Code and Antigravity compatibility-only fields from CLIProxyAPI revision
  `2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`, specifically
  `internal/auth/kimi/kimi.go`,
  `internal/runtime/executor/kimi_executor.go`,
  `internal/auth/antigravity/constants.go`,
  `internal/runtime/executor/antigravity_executor_request.go`,
  `internal/runtime/executor/antigravity_executor_credits.go`, and
  `sdk/cliproxy/antigravity_models.go`.

Antigravity is an opt-in pinned compatibility profile. The fixture and crate do
not embed its OAuth client credentials or imply that its internal API is public
or stable.
