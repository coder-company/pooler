# Universal turnkey gateway

The `gateway` preset mounts the endpoint families the selected provider
documents, without hand-authoring a route plan. It is provider-aware: pointing
it at OpenAI, Anthropic, or Gemini mounts that provider's surface and nothing
else.

```yaml
imports:
  - preset: gateway
    as: gateway
    with:
      bind: 127.0.0.1:8400
      provider: openai
      secret: env:POOLER_GATEWAY_KEY

version: 1
```

```sh
POOLER_GATEWAY_KEY=... pooler serve --config config/gateway.example.yaml
```

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `bind` | `127.0.0.1:8400` | Listener address. |
| `provider` | `openai` | A provider this build ships an endpoint for. Run `pooler providers` for the list. |
| `upstream_url` | shipped provider base URL | Overrides the base URL for a private deployment or a test loopback. |
| `websocket_url` | `wss://api.openai.com` | `ws`/`wss` upstream used by the semantic `POST /v1/responses` transport and the same-wire WebSocket upgrade route. These are mounted only for providers documenting the `responses` family. Set this whenever they are mounted and `provider` is not `openai`; `provider` selects the REST base URL only, while these routes require an explicit `ws`/`wss` transport. |
| `secret` | `env:POOLER_GATEWAY_KEY` | Secret reference for both upstreams. A reference only; never a literal. Only the reference is overridden: the provider's documented authentication kind, header name, and value prefix are preserved, so Anthropic receives `x-api-key` and Gemini receives `x-goog-api-key` rather than a bearer token. |

`as:` namespaces every listener, upstream, and route, so several gateways can
run in one process without colliding.

## What is mounted

The preset mounts a route only when the selected provider's shipped integration
documents that endpoint family **and** serves that wire surface. Mounting a path
a provider does not implement is not compatibility, so those routes are simply
absent rather than present and broken.

| Provider | Routes mounted |
| --- | --- |
| `openai` | `models`, `chat-completions`, `responses`, `responses-compact`, `responses-websocket`, `realtime-websocket`, `realtime-client-secrets`, legacy `realtime-sessions` / `realtime-transcription-sessions`, and four explicit `realtime-calls-*` actions |
| `xai` | `models`, `chat-completions`, `responses`, `responses-compact`, `responses-websocket` |
| `anthropic` | `models`, `messages`, `messages-count-tokens` |
| `google` | `gemini-models`, `gemini-model-get`, `gemini-model-actions`, and create/resource/cancel routes for `v1`, `v1beta`, and `v1beta2` Interactions |

| Route | Method and path | Family | Mode |
| --- | --- | --- | --- |
| `models` | `GET /v1/models` | `models` | served by Pooler |
| `chat-completions` | `POST /v1/chat/completions` | `chat_completions` | patch |
| `responses` | `POST /v1/responses` | `responses` | semantic Responses-over-WebSocket transport |
| `responses-compact` | `POST /v1/responses/compact` | `responses_compact` | bounded same-wire patch |
| `responses-websocket` | `GET /v1/responses` (upgrade) | `responses` | opaque tunnel |
| `realtime-websocket` | `GET /v1/realtime?model=...` or `?call_id=...` (upgrade) | `realtime` | bounded semantic same-wire validation; sideband reuses this route |
| `realtime-client-secrets` | `POST /v1/realtime/client_secrets` | `realtime_client_secrets` | bounded opaque same-wire |
| `realtime-sessions` | `POST /v1/realtime/sessions` | `realtime_sessions` | bounded opaque deprecated-beta same-wire |
| `realtime-transcription-sessions` | `POST /v1/realtime/transcription_sessions` | `realtime_transcription_sessions` | bounded opaque deprecated-beta same-wire |
| `realtime-calls-{accept,reject,refer,hangup}` | `POST /v1/realtime/calls/{call_id}/{action}` | `realtime_calls` | four exact bounded opaque same-wire routes |
| `messages` | `POST /v1/messages` | `messages` | patch |
| `messages-count-tokens` | `POST /v1/messages/count_tokens` | `messages` | patch |
| `gemini-models` | `GET /v1beta/models` | `models` | opaque discovery response |
| `gemini-model-get` | `GET /v1beta/models/{model}` | `models` | semantic selection, same-wire response |
| `gemini-model-actions` | `POST /v1beta/models/{model}:generateContent`, `:streamGenerateContent`, or `:countTokens` | `generate_content` | semantic selection, same-wire response |
| `gemini-interactions-*-create` | `POST /v1/interactions`, `/v1beta/interactions`, or `/v1beta2/interactions` | `interactions` | semantic selection, same-wire response |
| `gemini-interactions-*-resources` | `GET`/`DELETE .../interactions/{id}` | `interactions` | semantic affinity, same-wire response |
| `gemini-interactions-*-cancel` | `POST .../interactions/{id}/cancel` | `interactions` | semantic affinity, same-wire response |

The `models` routes are told apart by the provider's documented discovery path
rather than by dialect, so Anthropic keeps its OpenAI-shaped `/v1/models` list
while Gemini gets `/v1beta/models`. The Interactions versions follow Google's
current stable/beta reference plus the documented `v1beta2` migration surface.

Embeddings, images, audio, files, batches, and legacy completions are **not**
mounted when the selected provider does not document those families. They remain
available to hand-authored routes, where the operator asserts the endpoint
exists.

### Rejecting an unsupported combination

`target.endpoint_family` declares the family a route speaks. When the target
upstream names a `known_provider`, compilation rejects a family that provider
does not document:

```text
error: invalid configuration at gateway.yaml (routes[0]):
provider `openai` does not document the `messages` endpoint family
```

An upstream configured by URL has no documented family list, so the operator's
declaration stands.

## The served model view

`GET /v1/models` is answered by Pooler, not forwarded. The route declares
`serve: model_catalog`, so no upstream request is made and no credential is
materialized for it. The route's target still matters: it scopes which
provider's models are published and which capabilities they must satisfy.

The published list is the set of models this deployment will actually serve. It
applies the catalog's public aliases and exclusions, drops models an operator
has disabled at runtime, keeps only models whose target satisfies the route's
required capabilities, and keeps only models with at least one target whose
credential is enabled and not cooling down. A model nothing can serve is not
advertised, even when the upstream still lists it.

The response is the stable OpenAI list shape plus the configuration and catalog
generations:

```json
{
  "object": "list",
  "data": [{"id": "gpt-4o", "object": "model", "owned_by": "pooler"}],
  "configuration_generation": 1,
  "catalog_generation": 1
}
```

Provider IDs, upstream model names, account IDs, secret references, and
upstream endpoints are absent by construction, because only public model IDs
reach the response. `owned_by` is the constant `pooler` rather than the
provider, since naming the provider would disclose routing.

## What the two modes claim

`patch` parses the caller's JSON, rewrites only the `/model` pointer to the
selected target's upstream model, and forwards everything else unchanged. This
is what makes catalog aliases, account pooling, capability filtering, and the
vendored request-facts dialect apply to a request. A model the catalog does not
know is rejected before any upstream call.

Responses Compact has its own `responses_compact` endpoint family. Ordinary
Responses support no longer causes this route to be mounted accidentally. The
OpenAI and xAI integrations explicitly document the family; other
OpenAI-compatible providers do not receive the route. Pooler requires bounded
JSON with a non-empty model, performs normal model/account selection, strips
caller credentials, injects the selected provider credential, preserves all
other request fields, and returns the provider's `response.compaction` JSON
unchanged. The committed replay follows the executable OpenAI SDK 6.40.0
`POST /responses/compact` request and `CompactedResponse` shapes. It is strict
loopback evidence, not live-provider conformance, and Pi 0.84.2 does not invoke
this native endpoint for its `/compact` command.

No Alpha Search route is mounted. Neither the installed Pi 0.84.2 transport nor
its installed OpenAI SDK 6.40.0 contains an Alpha Search method, path, or wire
schema. Pooler will not infer that contract from ordinary web-search tools,
vector-store search, or xAI `search_parameters`.

OpenAI Realtime uses `GET /v1/realtime?model=...` over WebSocket. SIP sideband
connections reuse that mounted route as `GET /v1/realtime?call_id=...`; there is
no separate sideband route. Pooler preserves the query, strips caller `openai-insecure-api-key.*` subprotocols, injects
the selected operator credential, and forwards only the non-secret `realtime`
subprotocol. Accepted application messages remain byte-for-byte same-wire JSON,
but both directions are validated against the installed OpenAI SDK 6.40.0 event
set and lifecycle before forwarding. The validator covers session creation and
updates, base64 audio append/commit/output, conversation items, function tools,
response creation, interruption/cancellation, terminal status, errors, rate
limits, and MCP events. Unknown, malformed, binary, fragmented, out-of-order, or
over-limit application messages close with an appropriate WebSocket policy or
size error. A one-hour absolute age bounds each connection; cancellation and
drain close it. Because the downstream `101` commits the session, Pooler never
reconnects or replays it. Dedicated reasoning events are not claimed because the
SDK contract used as evidence defines none.

The REST control surface follows executable OpenAI SDK 6.40.0 methods exactly:
GA client secrets use `POST /realtime/client_secrets`; the deprecated beta
session and transcription-session creators use `POST /realtime/sessions` and
`POST /realtime/transcription_sessions` with `OpenAI-Beta: assistants=v2`; SIP
uses only `POST /realtime/calls/{call_id}/{accept,reject,refer,hangup}`. Pooler
mounts these as bounded opaque same-wire routes, preserves request and response
bodies, strips caller credentials, and injects the selected OpenAI credential.
Their endpoint families are listed only by the OpenAI provider, so selecting an
OpenAI-compatible, xAI, Anthropic, or Google provider removes them at compile
time. The SDK declares translation-session data types but exports no creation
method or HTTP path, so no translation-session endpoint is mounted.

The `responses` route is semantic. It decodes the OpenAI-compatible request,
performs normal model/account/capability selection, sends a bounded
`response.create` message to the provider WebSocket, validates every provider
event, and emits Responses SSE to the REST caller. OpenAI and xAI select their
respective request/event codecs. Tools, reasoning, usage, failures, incomplete
terminals, and completed terminals pass through the semantic lifecycle rather
than an unchecked frame tunnel.

A reusable provider connection requires an explicit downstream session identity
(`session-id`, `session_id`, `x-session-id`, `x-thread-id`, `x-conversation-id`,
`prompt_cache_key`, or supported metadata). Its identity also includes profile,
account, endpoint, and credential generation. A completed turn may use
`previous_response_id` only when request parameters and the exact canonical
request/response history prefix match; otherwise Pooler sends the full request.
Provider failures before the first event remain retryable, while the first event
commits the attempt. Cancellation closes active transport, and idle, absolute
age, frame, event, bootstrap, queue-byte, and queue-item bounds are enforced.
Retained continuation output shares the queue byte/item ceilings. The process-local
idle cache is capped at 128 connections and evicts the least recently used entry
when distinct caller sessions reach that cap.

`opaque` forwards bytes or frames without semantic decoding. Media, file, and
batch surfaces keep provider-specific fields exactly, and upload bytes are
streamed once so the retry policy cannot replay them.

**Opaque forwarding is not provider-native semantic compatibility.** The raw
`GET /v1/responses` WebSocket upgrade remains a same-wire tunnel. The semantic
`POST /v1/responses` route uses explicit request/event codecs but remains the
OpenAI-compatible Responses protocol on both sides; it is not cross-protocol
translation. Executable compatibility claims live in
`fixtures/compatibility/MATRIX.md`.

Gemini carries the model in a model-action path, except for Interactions create,
which carries `model` in its JSON body. These routes therefore use Gemini
semantic ingress rather than an OpenAI body inspector. The adapter rejects
unknown actions, extra path segments, and encoded separators before an upstream
call; extracts the public model and required capabilities; runs normal model,
account, and policy selection; rewrites a known public alias to its upstream
model; and preserves caller query parameters. Streaming GenerateContent alone
normalizes `alt` to the documented single `alt=sse` value.

A model already present in static configuration or the refreshed catalog is
resolved and capability-filtered. A provider model not in either source is sent
to the selected Google upstream unchanged, so the turnkey gateway does not turn
a newly released model into a local `unknown model` error. For Interactions,
known model aliases are rewritten in the body. Resource IDs and
`previous_interaction_id` are exposed as the `gemini.interaction_id` affinity
source, so a pooling policy can select follow-up operations consistently. Pooler
does not inspect opaque responses to bind a newly returned ID to the account that
created it; deployments that require that ownership guarantee must supply an
explicit caller affinity key or a single owning account. Agent-backed creates
have no model to rewrite and pass through after strict JSON validation.

The response remains provider-native Gemini JSON or SSE. “Semantic” here means
validated routing and selection, not a claim that Pooler translates Gemini into
a different client protocol.

## Where the model list comes from

The gateway upstream is declared with `known_provider`, so its base URL,
discovery parser, model aliases, and model exclusions come from the provider
catalog this build ships. Pooler then derives a catalog source for that upstream
automatically and discovers models at startup. That is what makes the preset
turnkey: the operator supplies a provider name and a secret reference, and the
patch routes select against the discovered catalog.

Because a `known_provider` upstream carries a native kind, the gateway needs a
real native runtime. `pooler serve` provides one. An embedder calling
`HttpProxyServer::bind` installs a disabled native runtime and startup discovery
will fail authorization before any transport; use
`HttpProxyServer::bind_with_native_runtime` instead.

## Limits

Every route declares explicit bounds. JSON routes cap the request body at
8 MiB; media, file, batch, and Gemini action routes cap it at 32 MiB. Streaming
routes additionally bound frame size, event size, bootstrap state, queue bytes,
and queue items. Semantic Responses connections also enforce per-turn idle and
request deadlines, cumulatively bound retained continuation state, cap the idle
pool, and enforce process-local idle-reuse and absolute-age ceilings.

## Evidence

Each claim above is backed by an executable test.

| Claim | Test |
| --- | --- |
| Preset expansion, alias isolation, parameter rejection, secret redaction | `crates/pooler-config/tests/gateway_preset.rs` |
| Each provider mounts only its documented families | `gateway_preset.rs::each_provider_mounts_only_its_documented_endpoint_families` |
| An undocumented family is refused at compile time | `gateway_preset.rs::an_undocumented_endpoint_family_is_rejected_at_compile_time` |
| Each provider receives only its documented credential placement | `crates/pooler-server/tests/gateway_provider_auth.rs` |
| Caller credential headers never reach a provider | `gateway_provider_auth.rs::client_supplied_credential_headers_never_reach_any_provider` |
| The credential reaches no management surface | `gateway_provider_auth.rs::the_upstream_credential_never_reaches_a_management_surface` |
| `/v1/models` serves the active view and hides routing | `crates/pooler-server/tests/gateway_models.rs` |
| A disabled or capability-mismatched model is not advertised | `gateway_models.rs::an_operator_disabled_model_leaves_the_published_view`, `::a_model_lacking_a_required_capability_is_not_published` |
| Caller body preservation and the bounded raw WebSocket tunnel | `crates/pooler-server/tests/gateway_preset.rs` |
| Mounted semantic Responses WebSocket authentication, tools, reasoning, usage, terminal state, session reuse, and continuation | `gateway_preset.rs::the_gateway_preset_uses_semantic_responses_websocket_with_continuation` |
| Responses Compact capability isolation, request preservation, credentials, response shape, and local malformed/model/size rejection | `gateway_preset.rs::responses_compact_replays_the_documented_same_wire_shape` |
| OpenAI Realtime authentication, secret-subprotocol stripping, query preservation, audio, tools, interruption, terminal state, and same-wire lifecycle | `gateway_preset.rs::the_gateway_preset_validates_openai_realtime_lifecycle` |
| Invalid Realtime client events stop before provider delivery | `gateway_preset.rs::openai_realtime_rejects_invalid_client_events_before_upstream_delivery` |
| Realtime client-secret, legacy session/transcription-session, and exact SIP control paths, headers, bodies, and credentials | `gateway_provider_auth.rs::openai_realtime_control_routes_match_the_sdk_wire_contract` |
| Sideband `call_id` query preservation on the existing Realtime WebSocket route | `gateway_preset.rs::openai_realtime_sideband_reuses_the_call_id_websocket_route` |
| Credential/session isolation, cancellation commitment, age ceilings, and bootstrap/queue bounds | `crates/pooler-http/src/openai_websocket.rs` unit tests |
| Strict Gemini model/action/Interactions paths and credentials | `gateway_provider_auth.rs::gemini_routes_satisfy_a_strict_gemini_endpoint` |
| Invalid Gemini actions and encoded separators never reach the provider | `gateway_provider_auth.rs::gemini_gateway_rejects_unknown_actions_and_encoded_model_separators_locally` |
| Gemini alias rewriting, capability context, and query preservation | `crates/pooler-server/tests/gemini_runtime.rs`, `crates/adapter-gemini/src/runtime.rs` unit tests |

Provider traffic is judged by `pooler_testkit::StrictProvider`, which enforces
path, method, credential placement, required headers, query shape, content
type, and body shape, and refuses anything else with the status the real
endpoint would use. `gateway_provider_auth.rs::the_strict_provider_refuses_a_request_the_endpoint_does_not_serve`
proves that fake is genuinely strict, so the other tests cannot pass because it
was generous.

## Not yet claimed

The native `GET /v1/responses` upgrade remains a bounded same-wire tunnel; Pooler
does not translate arbitrary downstream WebSocket frames. The committed semantic
fixture is strict-loopback evidence for the REST-to-WebSocket transport, not
live OpenAI or xAI provider conformance. Live-provider conformance for the preset
is a separate gate and has not been run. The same limit applies to Responses
Compact, and no Alpha Search compatibility is claimed.
