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
use pooler_core::{BodyMode, Capability};
use tempfile::TempDir;

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/gateway.example.yaml")
}

/// Every endpoint family the preset promises, as `(route id, method, path)`.
const MOUNTED_ROUTES: &[&str] = &[
    "gateway-models",
    "gateway-chat-completions",
    "gateway-completions",
    "gateway-responses",
    "gateway-responses-compact",
    "gateway-responses-websocket",
    "gateway-embeddings",
    "gateway-messages",
    "gateway-messages-count-tokens",
    "gateway-images",
    "gateway-audio",
    "gateway-files",
    "gateway-batches",
    "gateway-gemini-models",
    "gateway-gemini-model-actions",
    "gateway-gemini-interactions",
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
}

#[test]
fn the_gateway_preset_selects_models_through_the_catalog_and_preserves_other_bodies() {
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

    // Media and file surfaces never decode, so provider-specific fields and
    // upload bytes survive exactly.
    for id in [
        "gateway-images",
        "gateway-audio",
        "gateway-files",
        "gateway-batches",
    ] {
        let route = config.route(id).expect("opaque route");
        assert!(
            route.ingress().mode().preserves_original(),
            "{id} must not decode"
        );
        assert_eq!(route.limits().max_request_body_bytes, 32 * 1024 * 1024);
    }
    assert!(config
        .route("gateway-images")
        .expect("image route")
        .target()
        .capabilities()
        .contains(Capability::Images));

    // Gemini carries the model in the path, so those routes stay opaque rather
    // than pretending a body inspector can select a target.
    for id in [
        "gateway-gemini-models",
        "gateway-gemini-model-actions",
        "gateway-gemini-interactions",
    ] {
        let route = config.route(id).expect("gemini route");
        assert!(
            route.ingress().mode().preserves_original(),
            "{id} must not decode"
        );
        assert!(route.target().model_source().is_none(), "{id}");
    }
}

#[test]
fn the_gateway_websocket_route_uses_the_websocket_upstream() {
    let config = load_path(example_path())
        .expect("gateway example loads")
        .compile()
        .expect("gateway example compiles");

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

    assert_eq!(config.routes().len(), MOUNTED_ROUTES.len() * 2);
    assert_eq!(config.listeners()["first"].bind(), "127.0.0.1:18601");
    assert_eq!(config.listeners()["second"].bind(), "127.0.0.1:18602");
    assert_eq!(config.upstreams()["first"].known_provider(), Some("openai"));
    assert_eq!(
        config.upstreams()["second"].known_provider(),
        Some("anthropic")
    );
    assert_eq!(
        config.upstreams()["first"]
            .auth()
            .expect("first auth")
            .secret()
            .redacted(),
        "env:FIRST_KEY"
    );
    assert_eq!(
        config.upstreams()["second"]
            .auth()
            .expect("second auth")
            .secret()
            .redacted(),
        "env:SECOND_KEY"
    );
    assert_eq!(
        config
            .route("second-responses-websocket")
            .expect("second websocket route")
            .target()
            .upstream(),
        "second-websocket"
    );
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
