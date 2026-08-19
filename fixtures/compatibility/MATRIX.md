# Compatibility matrix

This report is generated from `fixtures/compatibility/manifest.json`. Reference-only rows do not claim compatibility with a current client or live provider.

| Adapter | Protocol | Fixture version | Equivalence | Evidence | Provenance | Notes | Fixture |
| --- | --- | --- | --- | --- | --- | --- | --- |
| codex | native-provider | status-gated-v1 | config_structural | not established | Pooler example configuration | No live provider authorization or conformance fixture is committed. | `../../config/pooler.example.yaml` |
| cursor | http-json-patch | preset-v1 | config_structural | not established | Pooler preset example | No current Cursor client fixture is committed; compatibility is not claimed. | `../../config/cursor.example.yaml` |
| devin | connect-rpc | v1 | protobuf_semantic | sanitized cross-language reference (compatibility not claimed) | sanitized widevin and oh-my-pi reference sources | This fixture is not evidence of compatibility with a current Devin client. | `../devin/connect/chat-stream.json` |
| factory | language-model-v3 | v3 | event_semantic | sanitized local reference (compatibility not claimed) | sanitized fx-cliproxy-bridge local reference | This fixture is not evidence of compatibility with a current Factory client. | `../factory/fx-cliproxy-bridge-v3.json` |
| factory | language-model-v3 | v3-text | json_structural | sanitized local reference (compatibility not claimed) | sanitized fx-cliproxy-bridge local reference | This fixture is not evidence of compatibility with a current Factory client. | `../factory/fx-cliproxy-bridge-text.json` |
