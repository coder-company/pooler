//! Expansion coverage for the universal turnkey gateway preset.
//!
//! These assertions cover the preset as configuration: what it declares, how
//! an alias isolates two gateways, and which parameters it refuses. Whether a
//! route is actually reachable is proved separately by the mounted
//! `HttpProxyServer` tests in `pooler-server`.

use std::io::Write;
use std::path::PathBuf;

use pooler_config::ModelSource;
use pooler_config::{load_path, render_path};
use pooler_core::{BodyMode, Capability, LossPolicy};
use tempfile::TempDir;

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/gateway.example.yaml")
}

/// The routes the shipped example mounts. The example selects OpenAI, whose
/// integration documents the OpenAI text, image, audio, video, Responses,
/// Realtime, and models families, so the Anthropic and Gemini surfaces are deliberately absent.
const MOUNTED_ROUTES: &[&str] = &[
    "gateway-models",
    "gateway-chat-completions",
    "gateway-completions",
    "gateway-embeddings",
    "gateway-files-list",
    "gateway-files-create",
    "gateway-files-content",
    "gateway-files-resource",
    "gateway-batches-list",
    "gateway-batches-create",
    "gateway-batches-cancel",
    "gateway-batches-resource",
    "gateway-responses",
    "gateway-responses-compact",
    "gateway-image-generations",
    "gateway-image-edits",
    "gateway-audio-transcriptions",
    "gateway-video-creations",
    "gateway-video-edits",
    "gateway-video-extensions",
    "gateway-video-remixes",
    "gateway-video-retrieval",
    "gateway-video-content",
    "gateway-video-deletions",
    "gateway-responses-websocket",
    "gateway-realtime-client-secrets",
    "gateway-realtime-sessions",
    "gateway-realtime-transcription-sessions",
    "gateway-realtime-calls-accept",
    "gateway-realtime-calls-reject",
    "gateway-realtime-calls-refer",
    "gateway-realtime-calls-hangup",
    "gateway-realtime-websocket",
];

#[test]
fn the_checked_in_gateway_example_mounts_every_promised_endpoint_family() {
    let config = load_path(example_path())
        .expect("gateway example loads")
        .compile()
        .expect("gateway example compiles");

    for id in MOUNTED_ROUTES {
        assert!(
            config.route(id).is_some(),
            "the gateway preset must mount {id}"
        );
    }
    assert_eq!(
        config.routes().len(),
        MOUNTED_ROUTES.len(),
        "the preset must not mount an undocumented route"
    );
    assert!(
        config
            .route("gateway-realtime-translation-sessions")
            .is_none(),
        "the SDK exposes translation types but no endpoint method/path"
    );
}

#[test]
fn the_gateway_preset_selects_models_and_mounts_semantic_responses_transport() {
    let config = load_path(example_path())
        .expect("gateway example loads")
        .compile()
        .expect("gateway example compiles");

    // A patch route rewrites only `/model`, so the caller's body survives while
    // catalog aliases, pooling, and the request-facts dialect still apply.
    let chat = config
        .route("gateway-chat-completions")
        .expect("chat route");
    assert_eq!(chat.ingress().mode(), BodyMode::Patch);
    assert_eq!(chat.target().model_source(), Some(ModelSource::Request));
    assert!(chat.response().mode().preserves_original());
    assert_eq!(chat.limits().max_request_body_bytes, 8 * 1024 * 1024);

    let responses = config.route("gateway-responses").expect("Responses route");
    assert_eq!(responses.ingress().mode(), BodyMode::Semantic);
    assert_eq!(
        responses.ingress().decoder(),
        Some("decode.openai.responses")
    );
    assert_eq!(
        responses.response().decoder(),
        Some("decode.openai.responses.events")
    );
    assert_eq!(responses.target().upstream(), "gateway");
    assert_eq!(
        responses.target().transport_upstream(),
        Some("gateway-websocket")
    );
    assert_eq!(responses.target().path(), Some("/v1/responses"));
    assert_eq!(responses.loss_policy(), LossPolicy::Reject);

    let compact = config
        .route("gateway-responses-compact")
        .expect("Responses Compact route");
    assert_eq!(compact.ingress().mode(), BodyMode::Patch);
    assert_eq!(compact.target().model_source(), Some(ModelSource::Request));
    assert!(compact.response().mode().preserves_original());
    assert_eq!(compact.limits().max_request_body_bytes, 8 * 1024 * 1024);

    let image_generations = config
        .route("gateway-image-generations")
        .expect("image generations route");
    assert!(image_generations.ingress().mode().preserves_original());
    assert!(image_generations
        .target()
        .capabilities()
        .contains(Capability::Images));
    assert_eq!(
        image_generations.limits().max_request_body_bytes,
        32 * 1024 * 1024
    );

    let image_edits = config
        .route("gateway-image-edits")
        .expect("image edits route");
    assert!(image_edits.ingress().mode().is_semantic());
    assert_eq!(
        image_edits.ingress().decoder(),
        Some("decode.media.multipart")
    );
    assert!(image_edits.response().mode().preserves_original());
    assert!(image_edits
        .target()
        .capabilities()
        .contains(Capability::Files));
    assert_eq!(
        image_edits
            .target()
            .codecs()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["decode.media.multipart"]
    );

    let audio_transcriptions = config
        .route("gateway-audio-transcriptions")
        .expect("audio transcriptions route");
    assert!(audio_transcriptions.ingress().mode().is_semantic());
    assert_eq!(
        audio_transcriptions.ingress().decoder(),
        Some("decode.media.multipart")
    );
    assert!(audio_transcriptions.response().mode().preserves_original());
    for capability in [
        Capability::Text,
        Capability::Audio,
        Capability::InputAudio,
        Capability::Files,
    ] {
        assert!(audio_transcriptions
            .target()
            .capabilities()
            .contains(capability));
    }
    assert_eq!(
        audio_transcriptions
            .target()
            .codecs()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["decode.media.multipart"]
    );
    assert_eq!(
        audio_transcriptions.limits().max_request_body_bytes,
        32 * 1024 * 1024
    );
    assert_eq!(
        audio_transcriptions.limits().max_frame_bytes,
        32 * 1024 * 1024
    );

    for id in [
        "gateway-video-creations",
        "gateway-video-edits",
        "gateway-video-extensions",
    ] {
        let route = config.route(id).expect("video multipart route");
        assert_eq!(route.ingress().mode(), BodyMode::Semantic);
        assert_eq!(route.ingress().decoder(), Some("decode.media.multipart"));
        assert!(route.response().mode().preserves_original());
        assert_eq!(
            route
                .target()
                .codecs()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            ["decode.media.multipart"]
        );
        assert_eq!(route.limits().max_request_body_bytes, 32 * 1024 * 1024);
        assert_eq!(route.limits().max_response_body_bytes, 1024 * 1024);
    }
    let video_creations = config
        .route("gateway-video-creations")
        .expect("video creation route");
    for capability in [Capability::Text, Capability::Images, Capability::Files] {
        assert!(video_creations.target().capabilities().contains(capability));
    }

    let video_remixes = config
        .route("gateway-video-remixes")
        .expect("video remix route");
    assert_eq!(video_remixes.ingress().mode(), BodyMode::Opaque);
    assert_eq!(video_remixes.matcher().methods().len(), 1);
    assert_eq!(video_remixes.matcher().methods()[0].as_ref(), "POST");
    assert_eq!(video_remixes.limits().max_request_body_bytes, 1024 * 1024);

    let video_retrieval = config
        .route("gateway-video-retrieval")
        .expect("video retrieval route");
    assert_eq!(video_retrieval.matcher().methods()[0].as_ref(), "GET");
    assert!(video_retrieval.response().mode().preserves_original());

    let video_content = config
        .route("gateway-video-content")
        .expect("video content route");
    assert_eq!(video_content.matcher().methods()[0].as_ref(), "GET");
    assert_eq!(
        video_content
            .matcher()
            .headers()
            .get("accept")
            .map(AsRef::as_ref),
        Some("application/binary")
    );
    assert_eq!(
        video_content.limits().max_response_body_bytes,
        256 * 1024 * 1024
    );

    let video_deletions = config
        .route("gateway-video-deletions")
        .expect("video deletion route");
    assert_eq!(video_deletions.matcher().methods()[0].as_ref(), "DELETE");
    assert!(video_deletions.response().mode().preserves_original());

    // Discovery stays opaque and selects no model.
    let models = config.route("gateway-models").expect("models route");
    assert!(models.ingress().mode().preserves_original());
    assert!(models.target().model_source().is_none());
}

#[test]
fn the_gateway_websocket_routes_use_the_websocket_upstream() {
    let config = load_path(example_path())
        .expect("gateway example loads")
        .compile()
        .expect("gateway example compiles");

    let semantic = config
        .route("gateway-responses")
        .expect("semantic Responses route");
    assert_eq!(semantic.target().upstream(), "gateway");
    assert_eq!(
        semantic.target().transport_upstream(),
        Some("gateway-websocket")
    );

    let realtime = config
        .route("gateway-realtime-websocket")
        .expect("Realtime WebSocket route");
    assert_eq!(realtime.ingress().mode(), BodyMode::Semantic);
    assert_eq!(
        realtime.ingress().decoder(),
        Some("decode.openai.realtime.client")
    );
    assert_eq!(
        realtime.response().decoder(),
        Some("decode.openai.realtime.events")
    );
    assert_eq!(realtime.target().upstream(), "gateway-websocket");
    assert_eq!(realtime.target().path(), Some("/v1/realtime"));
    assert_eq!(
        realtime.limits().request_timeout,
        Some(std::time::Duration::from_secs(60 * 60))
    );

    let socket = config
        .route("gateway-responses-websocket")
        .expect("websocket route");
    assert_eq!(socket.target().upstream(), "gateway-websocket");
    assert!(socket
        .target()
        .capabilities()
        .contains(Capability::WebSocket));
    assert_eq!(
        config.upstreams()["gateway-websocket"].url().scheme(),
        "wss"
    );
}

#[test]
fn the_gateway_upstream_uses_a_shipped_provider_so_discovery_is_automatic() {
    let config = load_path(example_path())
        .expect("gateway example loads")
        .compile()
        .expect("gateway example compiles");

    // `known_provider` is what makes the preset turnkey: Pooler derives the
    // base URL, discovery parser, aliases, and exclusions from the provider
    // catalog this build ships, and builds a catalog source automatically.
    assert_eq!(
        config.upstreams()["gateway"].known_provider(),
        Some("openai")
    );
    let catalog = config.catalog().expect("an automatic catalog source");
    assert!(
        catalog
            .sources()
            .iter()
            .any(|source| source.source().provider().as_str() == "gateway"),
        "the gateway upstream must have a discovery source"
    );
}

#[test]
fn two_gateway_aliases_stay_isolated() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("two.yaml");
    let mut file = std::fs::File::create(&path).expect("config file");
    write!(
        file,
        "imports:\n  - preset: gateway\n    as: first\n    with: {{bind: 127.0.0.1:18601, secret: 'env:FIRST_KEY'}}\n  - preset: gateway\n    as: second\n    with: {{bind: 127.0.0.1:18602, provider: anthropic, secret: 'env:SECOND_KEY'}}\n\nversion: 1\n"
    )
    .expect("config contents");
    drop(file);

    let config = load_path(&path)
        .expect("two gateways load")
        .compile()
        .expect("two gateways compile");

    assert_eq!(config.listeners()["first"].bind(), "127.0.0.1:18601");
    assert_eq!(config.listeners()["second"].bind(), "127.0.0.1:18602");
    assert_eq!(config.upstreams()["first"].known_provider(), Some("openai"));
    assert_eq!(
        config.upstreams()["second"].known_provider(),
        Some("anthropic")
    );

    // Each alias mounts only the surface its own provider documents.
    for id in MOUNTED_ROUTES {
        assert!(
            config
                .route(id.replace("gateway-", "first-").as_str())
                .is_some(),
            "{id}"
        );
    }
    assert!(config.route("second-messages").is_some());
    assert!(config.route("second-models").is_some());
    assert!(
        config.route("second-chat-completions").is_none(),
        "Anthropic does not document chat_completions"
    );
    assert!(
        config.route("first-messages").is_none(),
        "OpenAI does not document messages"
    );
}

/// A provider is served only the endpoint families it documents.
#[test]
fn each_provider_mounts_only_its_documented_endpoint_families() {
    let expected: [(&str, &[&str]); 4] = [
        (
            "openai",
            &[
                "gw-models",
                "gw-chat-completions",
                "gw-completions",
                "gw-embeddings",
                "gw-files-list",
                "gw-files-create",
                "gw-files-content",
                "gw-files-resource",
                "gw-batches-list",
                "gw-batches-create",
                "gw-batches-cancel",
                "gw-batches-resource",
                "gw-responses",
                "gw-responses-compact",
                "gw-image-generations",
                "gw-image-edits",
                "gw-audio-transcriptions",
                "gw-video-creations",
                "gw-video-edits",
                "gw-video-extensions",
                "gw-video-remixes",
                "gw-video-retrieval",
                "gw-video-content",
                "gw-video-deletions",
                "gw-responses-websocket",
                "gw-realtime-client-secrets",
                "gw-realtime-sessions",
                "gw-realtime-transcription-sessions",
                "gw-realtime-calls-accept",
                "gw-realtime-calls-reject",
                "gw-realtime-calls-refer",
                "gw-realtime-calls-hangup",
                "gw-realtime-websocket",
            ],
        ),
        (
            "xai",
            &[
                "gw-models",
                "gw-chat-completions",
                "gw-responses",
                "gw-responses-compact",
                "gw-responses-websocket",
            ],
        ),
        (
            "anthropic",
            &["gw-models", "gw-messages", "gw-messages-count-tokens"],
        ),
        (
            "google",
            &[
                "gw-gemini-models",
                "gw-gemini-model-get",
                "gw-gemini-model-actions",
                "gw-gemini-interactions-v1-create",
                "gw-gemini-interactions-v1-resources",
                "gw-gemini-interactions-v1-cancel",
                "gw-gemini-interactions-v1beta-create",
                "gw-gemini-interactions-v1beta-resources",
                "gw-gemini-interactions-v1beta-cancel",
                "gw-gemini-interactions-v1beta2-create",
                "gw-gemini-interactions-v1beta2-resources",
                "gw-gemini-interactions-v1beta2-cancel",
            ],
        ),
    ];

    for (provider, routes) in expected {
        let directory = TempDir::new().expect("config directory");
        let path = directory.path().join("gateway.yaml");
        std::fs::write(
            &path,
            format!(
                "imports:\n  - preset: gateway\n    as: gw\n    with: {{bind: 127.0.0.1:0, provider: {provider}, secret: 'env:K'}}\n\nversion: 1\n"
            ),
        )
        .expect("config contents");
        let config = load_path(&path)
            .expect("gateway loads")
            .compile()
            .expect("gateway compiles");

        let mounted: Vec<&str> = config.routes().iter().map(|route| route.id()).collect();
        assert_eq!(mounted.len(), routes.len(), "{provider}: {mounted:?}");
        for route in routes {
            assert!(mounted.contains(route), "{provider} must mount {route}");
        }
    }
}

#[test]
fn xai_gateway_uses_xai_semantics_for_the_responses_websocket_transport() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "imports:\n  - preset: gateway\n    as: gw\n    with: {bind: 127.0.0.1:0, provider: xai, websocket_url: 'wss://api.x.ai', secret: 'env:K'}\n\nversion: 1\n",
    )
    .expect("config contents");
    let config = load_path(&path)
        .expect("xAI gateway loads")
        .compile()
        .expect("xAI gateway compiles");
    let responses = config.route("gw-responses").expect("Responses route");

    assert_eq!(responses.ingress().decoder(), Some("decode.xai.responses"));
    assert_eq!(
        responses.response().decoder(),
        Some("decode.xai.responses.events")
    );
    assert_eq!(responses.target().upstream(), "gw");
    assert_eq!(
        responses.target().transport_upstream(),
        Some("gw-websocket")
    );
}

#[test]
fn route_transport_upstream_accepts_an_arbitrary_ws_upstream_name() {
    let config = pooler_config::compile_yaml(
        "explicit-transport-upstream.yaml",
        r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  model-provider: {url: http://127.0.0.1:1}
  dedicated-semantic-socket: {url: ws://127.0.0.1:2}
routes:
  - id: responses
    listen: local
    ingress: {mode: semantic, decoder: decode.openai.responses}
    target:
      provider: model-provider
      transport_upstream: dedicated-semantic-socket
    response: {mode: semantic, decoder: decode.openai.responses.events}
"#,
    )
    .expect("explicit transport config");
    let target = config.route("responses").expect("responses route").target();
    assert_eq!(target.upstream(), "model-provider");
    assert_eq!(
        target.transport_upstream(),
        Some("dedicated-semantic-socket")
    );
}

#[test]
fn route_transport_upstream_rejects_a_missing_upstream() {
    let error = pooler_config::compile_yaml(
        "missing-transport-upstream.yaml",
        r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {model-provider: {url: http://127.0.0.1:1}}
routes:
  - id: responses
    listen: local
    ingress: {mode: semantic}
    target:
      provider: model-provider
      transport_upstream: absent-socket
"#,
    )
    .expect_err("missing transport upstream must fail compilation");
    assert!(error.to_string().contains("absent-socket"), "{error}");
}

#[test]
fn route_transport_upstream_rejects_a_non_websocket_upstream() {
    let error = pooler_config::compile_yaml(
        "incompatible-transport-upstream.yaml",
        r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams:
  model-provider: {url: http://127.0.0.1:1}
  http-transport: {url: http://127.0.0.1:2}
routes:
  - id: responses
    listen: local
    ingress: {mode: semantic}
    target:
      provider: model-provider
      transport_upstream: http-transport
"#,
    )
    .expect_err("non-WebSocket transport upstream must fail compilation");
    assert!(
        error
            .to_string()
            .contains("transport_upstream must use a ws or wss transport"),
        "{error}"
    );
}

/// An endpoint family the provider does not document is a configuration error,
/// not a runtime surprise.
#[test]
fn an_undocumented_endpoint_family_is_rejected_at_compile_time() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("bad.yaml");
    std::fs::write(
        &path,
        "version: 1\nlisteners: {local: {bind: 127.0.0.1:0}}\nupstreams:\n  openai:\n    known_provider: openai\n    auth: {secret: env:K}\nroutes:\n  - id: anthropic-on-openai\n    listen: local\n    match: {methods: [POST], path: /v1/messages}\n    ingress: {mode: opaque}\n    target: {provider: openai, endpoint_family: messages}\n    response: {mode: opaque}\n",
    )
    .expect("config contents");

    let error = load_path(&path)
        .expect("config loads")
        .compile()
        .expect_err("an undocumented family is rejected");
    assert!(
        error
            .to_string()
            .contains("does not document the `messages` endpoint family"),
        "{error}"
    );
}

/// An upstream the operator configured by URL has no documented family list, so
/// their declaration stands.
#[test]
fn an_operator_configured_upstream_keeps_its_declared_family() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("private.yaml");
    std::fs::write(
        &path,
        "version: 1\nlisteners: {local: {bind: 127.0.0.1:0}}\nupstreams: {private: {url: 'http://127.0.0.1:9', auth: {secret: env:K}}}\nroutes:\n  - id: anything\n    listen: local\n    match: {methods: [POST], path: /v1/messages}\n    ingress: {mode: opaque}\n    target: {provider: private, endpoint_family: messages}\n    response: {mode: opaque}\n",
    )
    .expect("config contents");

    load_path(&path)
        .expect("config loads")
        .compile()
        .expect("an operator-configured upstream is not second-guessed");
}

#[test]
fn the_gateway_preset_rejects_an_unknown_parameter() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("bad.yaml");
    std::fs::write(
        &path,
        "imports:\n  - preset: gateway\n    with: {bogus: 1}\n\nversion: 1\n",
    )
    .expect("config contents");

    let error = load_path(&path).expect_err("an unknown parameter is rejected");
    assert!(
        error
            .to_string()
            .contains("unknown preset parameter `bogus`"),
        "{error}"
    );
}

#[test]
fn the_rendered_gateway_preset_never_contains_a_secret_value() {
    let rendered = render_path(example_path()).expect("rendered gateway preset");
    assert!(rendered.contains("env:POOLER_GATEWAY_KEY"));
    assert!(!rendered.contains("bearer_secret\n      secret: sk-"));
}

/// The loader and the published schema must agree on the preset list.
///
/// Regression: `gateway` was accepted by the loader while the schema's preset
/// enum still listed six names, so a config the runtime loads happily would be
/// rejected by any editor or CI step validating against the artifact. The
/// schema-check script could not catch it because both sides were generated
/// from the same stale literal.
#[test]
fn the_schema_preset_enum_matches_every_preset_the_loader_accepts() {
    let schema: serde_json::Value = serde_json::from_str(&pooler_config::render_config_schema())
        .expect("the rendered schema is JSON");
    let published = find_preset_enum(&schema).expect("the schema publishes a preset enum");

    for preset in [
        "cursor", "devin", "factory", "fx", "gateway", "media", "xai",
    ] {
        assert!(
            published.iter().any(|value| value == preset),
            "the schema must publish the `{preset}` preset; it lists {published:?}"
        );
        // And the loader must actually accept it, so neither side can drift
        // ahead of the other.
        let directory = TempDir::new().expect("config directory");
        let path = directory.path().join("preset.yaml");
        std::fs::write(
            &path,
            format!("imports:\n  - preset: {preset}\n\nversion: 1\n"),
        )
        .expect("config contents");
        let error = load_path(&path).err().map(|error| error.to_string());
        assert!(
            !error
                .as_deref()
                .is_some_and(|error| error.contains("unknown preset")),
            "the loader must accept the `{preset}` preset the schema publishes: {error:?}"
        );
    }
    assert_eq!(published.len(), 7, "{published:?}");
}

/// Return the `imports[].preset` enum values from the rendered schema.
fn find_preset_enum(schema: &serde_json::Value) -> Option<Vec<String>> {
    fn walk(value: &serde_json::Value) -> Option<Vec<String>> {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(preset) = map.get("preset").and_then(|preset| preset.get("enum")) {
                    return preset.as_array().map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_owned))
                            .collect()
                    });
                }
                map.values().find_map(walk)
            }
            serde_json::Value::Array(values) => values.iter().find_map(walk),
            _ => None,
        }
    }
    walk(schema)
}

/// A preset must override only the protected credential reference.
///
/// Regression: the gateway preset used to declare `kind: bearer_secret`
/// alongside its secret, which overrode the `known_provider` placement. Pointing
/// it at Anthropic or Gemini then sent a bearer token instead of the documented
/// `x-api-key` / `x-goog-api-key` credential header.
#[test]
fn a_gateway_alias_keeps_each_providers_documented_credential_placement() {
    // (preset provider, expected auth kind, expected credential header)
    let providers: [(&str, &str, Option<&str>); 3] = [
        ("openai", "bearer_secret", None),
        ("anthropic", "header", Some("x-api-key")),
        ("google", "header", Some("x-goog-api-key")),
    ];

    for (provider, expected_kind, expected_header) in providers {
        let directory = TempDir::new().expect("config directory");
        let path = directory.path().join("gateway.yaml");
        std::fs::write(
            &path,
            format!(
                "imports:\n  - preset: gateway\n    as: gw\n    with: {{bind: 127.0.0.1:0, provider: {provider}, secret: 'env:OPERATOR_KEY'}}\n\nversion: 1\n"
            ),
        )
        .expect("config contents");

        let config = load_path(&path)
            .expect("gateway loads")
            .compile()
            .expect("gateway compiles");

        // Both upstreams must authenticate the same documented way.
        for upstream in ["gw", "gw-websocket"] {
            let auth = config.upstreams()[upstream]
                .auth()
                .unwrap_or_else(|| panic!("{provider}/{upstream} auth"));
            assert_eq!(auth.kind(), expected_kind, "{provider}/{upstream}");
            assert_eq!(auth.header(), expected_header, "{provider}/{upstream}");
            // The operator's credential reference still wins.
            assert_eq!(
                auth.secret().redacted(),
                "env:OPERATOR_KEY",
                "{provider}/{upstream}"
            );
        }
    }
}

/// Naming any placement field takes ownership of the whole placement, so an
/// operator who really wants a different header still gets exactly that.
#[test]
fn an_explicit_placement_still_outranks_the_provider_default() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("explicit.yaml");
    std::fs::write(
        &path,
        "version: 1\nupstreams:\n  private:\n    known_provider: anthropic\n    auth:\n      kind: header\n      header: x-private-key\n      value_prefix: 'Token '\n      secret: env:PRIVATE_KEY\n",
    )
    .expect("config contents");

    let config = load_path(&path)
        .expect("explicit auth loads")
        .compile()
        .expect("explicit auth compiles");
    let auth = config.upstreams()["private"].auth().expect("auth");
    assert_eq!(auth.kind(), "header");
    assert_eq!(auth.header(), Some("x-private-key"));
    assert_eq!(auth.value_prefix(), Some("Token "));
    assert_eq!(auth.secret().redacted(), "env:PRIVATE_KEY");
}

/// With no `auth` block at all the provider's documented environment variable
/// remains the credential reference.
#[test]
fn a_known_provider_without_an_auth_block_keeps_its_documented_reference() {
    let directory = TempDir::new().expect("config directory");
    let path = directory.path().join("documented.yaml");
    std::fs::write(
        &path,
        "version: 1\nupstreams:\n  anthropic:\n    known_provider: anthropic\n",
    )
    .expect("config contents");

    let config = load_path(&path)
        .expect("documented auth loads")
        .compile()
        .expect("documented auth compiles");
    let auth = config.upstreams()["anthropic"].auth().expect("auth");
    assert_eq!(auth.kind(), "header");
    assert_eq!(auth.header(), Some("x-api-key"));
    assert_eq!(auth.secret().redacted(), "env:ANTHROPIC_API_KEY");
}
