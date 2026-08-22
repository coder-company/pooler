//! `/v1/models` serves Pooler's active model view, not the upstream's list.
//!
//! These tests prove the difference is real rather than cosmetic: a model the
//! upstream advertises disappears from the published list once an operator
//! disables it or once the route requires a capability the model lacks.

use std::io::Write;
use std::sync::Arc;

use pooler_auth::MemoryOAuthTokenStore;
use pooler_http::{NativeRuntime, PoolingCoordinator};
use pooler_server::HttpProxyServer;
use pooler_testkit::{ProviderContract, StrictProvider};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "models-view-key";

/// Build a gateway whose upstream advertises `gpt-4o`, optionally requiring a
/// capability on the models route.
fn gateway_config(
    directory: &TempDir,
    upstream: std::net::SocketAddr,
    required_capability: Option<&str>,
) -> pooler_config::CompiledConfig {
    let mut secret_file = tempfile::NamedTempFile::new_in(directory.path()).expect("secret file");
    secret_file
        .write_all(SECRET.as_bytes())
        .expect("secret contents");
    let (_, secret) = secret_file.keep().expect("secret persists");
    let capabilities = required_capability
        .map(|capability| format!("      capabilities: [{capability}]\n"))
        .unwrap_or_default();
    let text = format!(
        "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  gateway:\n    known_provider: openai\n    url: http://{upstream}\n    auth: {{secret: 'file:{}'}}\nroutes:\n  - id: models\n    listen: local\n    match: {{methods: [GET], path: /v1/models}}\n    serve: model_catalog\n    ingress: {{mode: opaque}}\n    target:\n      provider: gateway\n      endpoint_family: models\n{capabilities}    response: {{mode: opaque}}\n",
        secret.display()
    );
    pooler_config::compile_yaml("gateway-models.yaml", &text).expect("config compiles")
}

async fn published_models(
    config: pooler_config::CompiledConfig,
    pooling: Arc<PoolingCoordinator>,
) -> serde_json::Value {
    let native = Arc::new(
        NativeRuntime::new(&config, Arc::new(MemoryOAuthTokenStore::new()))
            .expect("native runtime"),
    );
    let server = HttpProxyServer::bind_with_native_runtime_and_pooling(config, native, pooling)
        .await
        .expect("gateway binds");
    let proxy = server.listener_addresses()[0].address().to_owned();
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut stream = TcpStream::connect(&proxy).await.expect("proxy connection");
    stream
        .write_all(b"GET /v1/models HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("request");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("response");

    server.begin_drain();
    runner.await.expect("server task").expect("server shutdown");

    let response = String::from_utf8_lossy(&bytes).to_string();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .expect("response body");
    serde_json::from_str(&body).expect("model view is JSON")
}

fn ids(view: &serde_json::Value) -> Vec<String> {
    view["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|model| model["id"].as_str().expect("model id").to_owned())
        .collect()
}

#[tokio::test]
async fn the_models_route_serves_the_active_view_in_the_openai_shape() {
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), None);
    let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling"));
    let view = published_models(config, pooling).await;
    let log = upstream.finish().await;
    log.assert_accepted_everything();

    assert_eq!(view["object"], "list");
    assert_eq!(
        ids(&view),
        vec!["gpt-4o".to_owned(), "text-embedding-3-small".to_owned()]
    );
    assert_eq!(view["data"][0]["object"], "model");
    assert!(view["configuration_generation"].is_u64());
    assert!(view["catalog_generation"].is_u64());

    // The published view must not disclose how the model is reached.
    let rendered = view.to_string();
    for leaked in [
        "provider",
        "upstream",
        "account",
        "secret",
        "127.0.0.1",
        "known_provider",
    ] {
        assert!(
            !rendered.contains(leaked),
            "the model view leaked `{leaked}`: {rendered}"
        );
    }
}

#[tokio::test]
async fn an_operator_disabled_model_leaves_the_published_view() {
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let directory = TempDir::new().expect("config directory");
    let config = gateway_config(&directory, upstream.address(), None);
    let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling"));

    // The upstream still advertises both models; Pooler must remove only the
    // operator-disabled model and keep the independently eligible embedding model.
    pooling
        .set_model_enabled("gpt-4o", false)
        .expect("disable model");

    let view = published_models(config, pooling).await;
    let log = upstream.finish().await;
    log.assert_accepted_everything();

    assert_eq!(
        ids(&view),
        vec!["text-embedding-3-small".to_owned()],
        "a disabled model must not be advertised: {view}"
    );
}

#[tokio::test]
async fn a_model_lacking_a_required_capability_is_not_published() {
    let upstream = StrictProvider::start(ProviderContract::openai(), SECRET).await;
    let directory = TempDir::new().expect("config directory");
    // The discovered OpenAI model does not advertise embeddings, so a route
    // requiring it must publish nothing rather than advertise an unusable model.
    let config = gateway_config(&directory, upstream.address(), Some("embeddings"));
    let pooling = Arc::new(PoolingCoordinator::new(&config).expect("pooling"));
    let view = published_models(config, pooling).await;
    let log = upstream.finish().await;
    log.assert_accepted_everything();

    assert!(
        ids(&view).is_empty(),
        "capability filtering must apply: {view}"
    );
}
