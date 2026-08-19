# Factory reference fixture

`fx-cliproxy-bridge-text.json` is a sanitized, deterministic text-stream
reference for
the translation implemented by `/home/chaitanya/fx-cliproxy-bridge/server.mjs`.
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

`fx-cliproxy-bridge-v3.json` is the broader event-semantic fixture. It adds
reasoning and fragmented tool-call input coverage while keeping the same local
reference and compatibility limitation.
