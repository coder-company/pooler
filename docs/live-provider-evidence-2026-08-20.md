# Live provider conformance — 2026-08-20

Pooler was run on loopback with the existing CLIProxyAPI Plus service as its
credential-bearing upstream. Pooler resolved only the CLIProxy client-key
reference in process; provider credentials remained inside CLIProxyAPI and no
credential value was printed, persisted, or committed.

The test used Pooler's ordinary opaque OpenAI-compatible route rather than a
mock provider. Results:

| Scenario | Result |
| --- | --- |
| Model discovery | HTTP 200; 72 sanitized model IDs |
| Non-stream Chat Completions | HTTP 200; assistant completion and usage |
| Streaming SSE | HTTP 200; valid incremental events and one `[DONE]` |
| Reasoning | `gpt-5.4` returned reasoning fields and detailed usage |
| Function tool call | One valid `get_weather` call with typed arguments |
| Tool-result follow-up | Provider accepted the tool result and completed the turn |
| Unknown model | Structured HTTP 400 `invalid_request_error` |
| Cancellation | Client cancellation did not terminate or destabilize Pooler |
| Redaction | Authorization sentinels were absent from responses and sanitized evidence |

This establishes live OpenAI-compatible provider forwarding, streaming,
reasoning, tools, error propagation, and cancellation through Pooler. It does
not establish native Anthropic, Gemini, xAI, Kimi, image, audio, or file
adapters; those remain separate provider-specific compatibility claims.

## Installed-client results

These are separate products and are reported separately. In particular,
Factory's `fx` CLI is not Factory Droid.

| Client | Installed version | Path exercised | Result |
| --- | --- | --- | --- |
| Cursor | 2026.08.04 | OpenAI-compatible text and streaming through Pooler | Pass |
| Factory `fx` | 0.0.3 | Factory V4 semantic route through Pooler | Text pass; terminal-tool lifecycle remains under investigation |
| Factory Droid | 0.149.0 | OpenAI Responses through Pooler | Pass; exact `POOLER_DROID_LIVE_OK` result with usage |
| Devin | installed CLI and local bridge | Devin metadata and semantic chat through Pooler | Text pass |
| Devin | installed CLI and local bridge | Terminal tool call and follow-up through Pooler | Pass; the client created a file containing the requested exact marker |

After the native protocol expansion, the following bridge-free checks also
passed against real providers through CLIProxyAPI's existing credentials:

| Client/protocol | Native Pooler path | Result |
| --- | --- | --- |
| FX 0.0.3 text | AI LanguageModel V3 -> OpenAI Chat | Pass; exact `POOLER_NATIVE_FX_TEXT_OK` |
| FX 0.0.3 tool loop | AI LanguageModel V3 -> OpenAI Chat | Pass; one real `file_info` call and exact `POOLER_NATIVE_FX_TOOL_OK` follow-up |
| Droid 0.149.0 OpenAI | OpenAI Responses | Pass; exact `POOLER_NATIVE_DROID_OK` with usage |
| Droid 0.149.0 Anthropic | Anthropic Messages | Pass; exact `POOLER_NATIVE_ANTHROPIC_OK` with usage |
| Gemini streaming | Gemini `streamGenerateContent` | The route reached the provider, which returned `PERMISSION_DENIED` for both available Foundry Gemini aliases; no completion compatibility claim is made |

The first native FX run exposed a current-client wire change: FX now sent the
reasoning effort as a string instead of the previously captured object. Pooler
normalizes that observed representation and has a regression test for it.

Droid required `/v1/responses`; the first run correctly failed with Pooler's
`404 no route matched` when the temporary listener exposed only
`/v1/chat/completions`. After adding an opaque Responses route, the same
installed Droid model completed successfully. This is direct evidence of a
client-specific endpoint requirement, not evidence that Chat Completions and
Responses are interchangeable.

The temporary Droid test changed one existing custom model's base URL only for
the duration of the process. The original settings file was restored
byte-for-byte after the run. No credential value was printed or committed.
