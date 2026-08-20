use http::{header, HeaderMap, HeaderValue};
use pooler_config::compile_yaml;
use pooler_core::Capability;
use pooler_http::{
    MediaSemanticAdapter, SemanticAdapter, MEDIA_BINARY_DECODER, MEDIA_MULTIPART_DECODER,
};
use pooler_protocol::{
    encode_multipart_media, ContentPart, MediaLimits, MediaSource, MultipartMediaPart,
};

fn route(decoder: &str, body_limit: usize) -> (pooler_config::CompiledConfig, String) {
    let route_id = decoder.replace('.', "-");
    let config = compile_yaml(
        "media-adapter.yaml",
        &format!(
            r#"
version: 1
listeners: {{local: {{bind: 127.0.0.1:1}}}}
upstreams: {{local: {{url: http://127.0.0.1:2}}}}
routes:
  - id: {route_id}
    listen: local
    match: {{methods: [POST], path: /media}}
    limits: {{max_request_body_bytes: {body_limit}, max_frame_bytes: {body_limit}}}
    ingress: {{mode: semantic, decoder: {decoder}}}
    target:
      provider: local
      capabilities: [text, images, audio, input_audio, files]
      codecs: [{decoder}]
    response: {{mode: opaque}}
"#
        ),
    )
    .expect("media route compiles");
    (config, route_id)
}

fn headers(content_type: HeaderValue) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type);
    headers
}

#[test]
fn raw_media_is_validated_preserved_and_drives_capability_selection() {
    let adapter = MediaSemanticAdapter::default();
    for (media_type, body, required) in [
        ("image/png", b"png".as_slice(), Capability::Images),
        ("audio/wav", b"wav".as_slice(), Capability::Audio),
        ("application/pdf", b"pdf".as_slice(), Capability::Files),
    ] {
        let (config, route_id) = route(MEDIA_BINARY_DECODER, 32);
        let route = config.route(&route_id).expect("binary route");
        let content_type = HeaderValue::from_str(media_type).expect("content type");
        let headers = headers(content_type.clone());

        assert!(adapter.supports(route));
        let context = adapter
            .selection_context(route, &headers, body)
            .expect("selection context");
        assert!(context.required_capabilities().contains(required));
        if media_type.starts_with("audio/") {
            assert!(context
                .required_capabilities()
                .contains(Capability::InputAudio));
        }
        assert_eq!(context.codec(), Some(MEDIA_BINARY_DECODER));

        let encoded = adapter
            .encode_request(route, &headers, body)
            .expect("encoded request");
        assert_eq!(encoded.body, body);
        assert_eq!(encoded.content_type, content_type);
    }
}

#[test]
fn multipart_validation_preserves_bytes_and_derives_every_media_capability() {
    let parts = vec![
        MultipartMediaPart::text("prompt", "describe"),
        MultipartMediaPart::media(
            "image",
            None,
            ContentPart::image("image/png", MediaSource::inline([1, 2, 3])),
        ),
        MultipartMediaPart::media(
            "audio",
            None,
            ContentPart::audio("audio/wav", MediaSource::inline([4, 5, 6])),
        ),
        MultipartMediaPart::media(
            "file",
            Some("notes.txt".to_owned()),
            ContentPart::file(
                Some("notes.txt".to_owned()),
                "text/plain",
                MediaSource::inline(b"notes".to_vec()),
            ),
        ),
    ];
    let media_limits = MediaLimits {
        max_body_bytes: 4096,
        max_part_bytes: 1024,
        max_parts: 8,
        max_header_bytes: 1024,
        max_headers_per_part: 4,
    };
    let multipart =
        encode_multipart_media(&parts, "pooler-http", media_limits).expect("multipart fixture");
    let (config, route_id) = route(MEDIA_MULTIPART_DECODER, 4096);
    let route = config.route(&route_id).expect("multipart route");
    let content_type = HeaderValue::from_str(&multipart.content_type).expect("content type");
    let headers = headers(content_type.clone());
    let adapter = MediaSemanticAdapter::new(media_limits);

    let context = adapter
        .selection_context(route, &headers, &multipart.body)
        .expect("selection context");
    for capability in [
        Capability::Text,
        Capability::Images,
        Capability::Audio,
        Capability::InputAudio,
        Capability::Files,
    ] {
        assert!(context.required_capabilities().contains(capability));
    }
    assert_eq!(context.codec(), Some(MEDIA_MULTIPART_DECODER));

    let encoded = adapter
        .encode_request(route, &headers, &multipart.body)
        .expect("encoded request");
    assert_eq!(encoded.body, multipart.body);
    assert_eq!(encoded.content_type, content_type);
}

#[test]
fn route_and_codec_limits_fail_closed() {
    let adapter = MediaSemanticAdapter::default();
    let (config, route_id) = route(MEDIA_BINARY_DECODER, 3);
    let binary_route = config.route(&route_id).expect("binary route");
    let binary_headers = headers(HeaderValue::from_static("image/png"));
    assert!(adapter
        .selection_context(binary_route, &binary_headers, b"four")
        .expect_err("route body limit")
        .to_string()
        .contains("3 byte limit"));

    let (config, route_id) = route(MEDIA_MULTIPART_DECODER, 1024);
    let multipart_route = config.route(&route_id).expect("multipart route");
    let multipart_headers = headers(HeaderValue::from_static(
        "multipart/form-data; boundary=missing",
    ));
    assert!(adapter
        .encode_request(multipart_route, &multipart_headers, b"not multipart")
        .expect_err("malformed multipart")
        .to_string()
        .contains("malformed multipart body"));
}

#[test]
fn content_type_and_route_contracts_are_explicit() {
    let adapter = MediaSemanticAdapter::default();
    let (config, route_id) = route(MEDIA_BINARY_DECODER, 1024);
    let route = config.route(&route_id).expect("binary route");
    assert!(adapter
        .selection_context(route, &HeaderMap::new(), b"x")
        .expect_err("missing content type")
        .to_string()
        .contains("exactly one valid content-type"));
    let headers = headers(HeaderValue::from_static("multipart/form-data; boundary=b"));
    assert!(adapter
        .selection_context(route, &headers, b"--b--\r\n")
        .expect_err("wrong decoder")
        .to_string()
        .contains("does not accept multipart"));

    let unsupported = compile_yaml(
        "media-response.yaml",
        r#"
version: 1
listeners: {local: {bind: 127.0.0.1:1}}
upstreams: {local: {url: http://127.0.0.1:2}}
routes:
  - id: unsupported
    listen: local
    ingress: {mode: semantic, decoder: decode.media.binary}
    target: local
    response: {mode: semantic, decoder: decode.any, encoder: encode.any}
"#,
    )
    .expect("unsupported route still compiles");
    assert!(!adapter.supports(unsupported.route("unsupported").expect("unsupported route")));
}
