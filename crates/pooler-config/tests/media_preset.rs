use std::path::PathBuf;

use pooler_config::{load_path, render_config_schema, render_path};
use pooler_core::Capability;

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/media.example.yaml")
}

#[test]
fn checked_in_media_example_expands_to_bounded_opaque_and_multipart_routes() {
    let path = example_path();
    let config = load_path(&path)
        .expect("media example loads")
        .compile()
        .expect("media example compiles");
    assert_eq!(config.listeners()["media"].bind(), "127.0.0.1:18476");
    assert_eq!(
        config.upstreams()["media"].url().as_str(),
        "http://127.0.0.1:8319/"
    );
    assert_eq!(
        config.upstreams()["media"]
            .auth()
            .expect("media auth")
            .secret()
            .redacted(),
        "env:POOLER_UPSTREAM_KEY"
    );

    let opaque = config.route("media-images").expect("opaque image route");
    assert_eq!(opaque.target().upstream(), "media");
    assert!(opaque.ingress().mode().preserves_original());
    assert_eq!(opaque.limits().max_request_body_bytes, 32 * 1024 * 1024);
    assert!(opaque.target().capabilities().contains(Capability::Images));

    let multipart = config
        .route("media-image-edits")
        .expect("validated multipart route");
    assert!(multipart.ingress().mode().is_semantic());
    assert_eq!(
        multipart.ingress().decoder(),
        Some("decode.media.multipart")
    );
    assert!(multipart.response().mode().preserves_original());
    assert_eq!(
        multipart
            .target()
            .codecs()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["decode.media.multipart"]
    );

    let batch = config.route("media-batches").expect("batch route");
    assert!(batch.target().capabilities().contains(Capability::Batch));

    let rendered = render_path(path).expect("rendered media preset");
    assert!(rendered.contains("decode.media.multipart"));
    assert!(rendered.contains("media-audio-transcriptions"));
    assert!(!rendered.contains("preset:"));
}

#[test]
fn generated_schema_advertises_the_media_preset() {
    let schema: serde_json::Value =
        serde_json::from_str(&render_config_schema()).expect("generated schema JSON");
    let presets = schema["$defs"]["import"]["oneOf"][2]["properties"]["preset"]["enum"]
        .as_array()
        .expect("preset enum");
    assert!(presets.iter().any(|preset| preset == "media"));
}
