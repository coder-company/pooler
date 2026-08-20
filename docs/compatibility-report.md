# Compatibility evidence

The checked-in matrix is a report of evidence, not a list of route-name
promises. Its input is [`fixtures/compatibility/manifest.json`](../fixtures/compatibility/manifest.json)
and its generated output is [`fixtures/compatibility/MATRIX.md`](../fixtures/compatibility/MATRIX.md).

Regenerate and verify the report from the repository root:

```sh
./scripts/check-compatibility-report.sh
```

Each row records two different things:

- `supported_capabilities` identifies the capability surface exercised by the
  sanitized fixture or structural route example.
- `unsupported_capabilities` identifies capabilities intentionally outside that
  fixture, or capabilities for which the row has no evidence. It is not a
  promise that every future route will reject the capability.

The evidence status is authoritative:

| Status | What it proves | What it does not prove |
| --- | --- | --- |
| `not_established` | A Pooler example or route shape exists. | A current client or live provider works. |
| `sanitized_local_reference` | The codec and fixture agree with a sanitized local reference. | Compatibility with a current Factory/client release. |
| `sanitized_cross_language` | The wire representation agrees with a pinned, sanitized cross-language source. | Compatibility with a current Devin client or service. |
| `current_client_conformance` | A reproducible current-client fixture and replay run passed. | Live-provider authorization or policy approval. |
| `live_provider_conformance` | A reproducible live-provider run passed under its recorded account and terms. | Compatibility with untested clients or provider versions. |

Pooler must not promote a reference row to a current-client or live-provider
status without a sanitized fixture, provenance, replay command, and passing
differential comparison. Provider authorization, terms, and secrets remain
outside the repository and are never committed.
