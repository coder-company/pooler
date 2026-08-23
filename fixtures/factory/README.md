# Factory reference fixture

`factory-v3-text-reference.json` is a sanitized, deterministic text-stream
reference captured during the initial Factory compatibility work.
It contains no credentials, provider URLs, workspace paths, or live-client
capture. The replay test uses the bridge's documented request and streamed
response shapes as a compatibility baseline for Pooler's Factory and OpenAI
Chat codecs.

The request checks model-header selection, prompt conversion, function-tool
conversion, tool choice, sampling fields, and reasoning effort. The response
checks metadata, text lifecycle, usage, finish state, and the `[DONE]` marker.

The bridge's metadata event omits the upstream response ID, and its usage
event exposes only aggregate input/output totals. Its finish event also keeps
the raw `stop` spelling. Pooler's Factory event shape preserves the response
ID, exposes derived `noCache` and `text` fields, and treats `stop` as the
unified finish reason. The fixture records those as intentional semantic
corrections; the replay test compares both the structured Pooler output and the
source-shaped projection.

This fixture proves codec behavior against a sanitized local reference. It is
not evidence of compatibility with a live Factory client or service.

`factory-v3-reference.json` is the broader event-semantic fixture. It adds
reasoning and fragmented tool-call input coverage while keeping the same local
reference and compatibility limitation.

'fx-0.0.3-v4-current-client.json' records the installed fx/0.0.3 client
through Pooler on 2026-08-20. It preserves the observed V4 specification and
Gateway protocol headers, a representative tool shape, the OpenAI forwarding
request, and the deterministic loopback stream. Prompt text, tool prose and
schemas, authorization, session identity, and transport-only headers are
redacted. The provider-defined search tool is explicitly recorded as an
optional loss under the preset's degrade policy.

Replay the exact sanitized request and deterministic stream through the real
HTTP proxy runtime with:

    cargo test -p pooler-server --test current_client_compatibility \
      factory_current_fixture_replays_through_http_proxy_server --locked

The adapter-only differential test remains available as:

    cargo test -p adapter-factory --test factory_current_fixture --locked

This is current-client request/stream conformance evidence only; it does not
authorize a live provider or claim broader Factory feature compatibility.
