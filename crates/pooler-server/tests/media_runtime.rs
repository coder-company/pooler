use std::{
    convert::Infallible,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pooler_config::{compile_yaml, CompiledConfig};
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn opaque_raw_media_preserves_bytes_and_rejects_declared_oversize_bodies() {
    let upstream = RecordingUpstream::start(201, b"stored").await;
    let running = start_server(opaque_config(upstream.address, 4, None)).await;

    let body = b"\x89PNG";
    let response = send_request(running.address, "/v1/images/raw", "image/png", body, "").await;
    assert_eq!(response_status(&response), 201);
    upstream.wait_for_attempts(1).await;
    let requests = upstream.requests();
    assert_eq!(http_body(&requests[0]), body);
    assert_eq!(
        header_value(&requests[0], "content-type"),
        Some("image/png")
    );

    let response = send_request(running.address, "/v1/images/raw", "image/png", b"12345", "").await;
    assert_eq!(response_status(&response), 413);
    sleep(Duration::from_millis(25)).await;
    assert_eq!(upstream.attempts(), 1, "oversize body reached upstream");

    running.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn opaque_chunked_upload_limits_return_413_and_preserve_exact_limit_success() {
    let upstream = RecordingUpstream::start(200, b"stored").await;
    let running = start_server(streaming_limit_config(upstream.address, "3s")).await;

    let aggregate = send_chunked_request(
        running.address,
        "/aggregate",
        "application/octet-stream",
        &[b"aaaaaa", b"bbbbbb"],
        "",
    )
    .await;
    assert_eq!(response_status(&aggregate), 413);
    assert!(http_body(&aggregate)
        .windows(b"request_too_large".len())
        .any(|window| window == b"request_too_large"));

    let frame = send_chunked_request(
        running.address,
        "/frame",
        "application/octet-stream",
        &[b"ffffff"],
        "",
    )
    .await;
    assert_eq!(response_status(&frame), 413);

    let exact = send_chunked_request(
        running.address,
        "/exact",
        "application/octet-stream",
        &[b"1234", b"5678"],
        "",
    )
    .await;
    assert_eq!(response_status(&exact), 200);
    upstream.wait_for_attempts(2).await;
    assert!(upstream.requests().iter().any(|request| {
        request.starts_with(b"POST /exact HTTP/1.1")
            && request
                .windows(b"1234".len())
                .any(|window| window == b"1234")
            && request
                .windows(b"5678".len())
                .any(|window| window == b"5678")
    }));

    running.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn fully_received_rejected_upload_keeps_the_downstream_connection_aligned() {
    let upstream = RecordingUpstream::start(200, b"stored").await;
    let running = start_server(streaming_limit_config(upstream.address, "3s")).await;
    let mut downstream = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    downstream
        .write_all(
            b"POST /aggregate HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n6\r\naaaaaa\r\n6\r\nbbbbbb\r\n0\r\n\r\n",
        )
        .await
        .expect("overflow request");
    let rejected = read_http_response(&mut downstream).await;
    assert_eq!(response_status(&rejected), 413);

    downstream
        .write_all(
            b"POST /exact HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\nConnection: close\r\n\r\n12345678",
        )
        .await
        .expect("follow-up request");
    let mut accepted = Vec::new();
    timeout(TEST_TIMEOUT, downstream.read_to_end(&mut accepted))
        .await
        .expect("follow-up response timeout")
        .expect("follow-up response");
    assert_eq!(response_status(&accepted), 200);

    running.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn rejected_upload_before_request_eos_closes_the_downstream_connection() {
    let upstream = RecordingUpstream::start(200, b"stored").await;
    let running = start_server(streaming_limit_config(upstream.address, "3s")).await;
    let mut downstream = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    downstream
        .write_all(
            b"POST /aggregate HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n6\r\naaaaaa\r\n6\r\nbbbbbb\r\n",
        )
        .await
        .expect("incomplete overflow request");
    let rejected = read_http_response(&mut downstream).await;
    assert_eq!(response_status(&rejected), 413);

    let _ = downstream
        .write_all(
            b"0\r\n\r\nPOST /exact HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\nConnection: close\r\n\r\n12345678",
        )
        .await;
    let mut trailing = Vec::new();
    timeout(TEST_TIMEOUT, downstream.read_to_end(&mut trailing))
        .await
        .expect("rejected downstream close timeout")
        .expect("rejected downstream closes");
    assert!(
        trailing.is_empty(),
        "incomplete rejected request admitted a pipelined response: {}",
        String::from_utf8_lossy(&trailing)
    );

    running.wait_for_request_idle().await;
    running.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn cancelled_chunked_upload_aborts_its_upstream_connection() {
    let (upstream_address, response_written, upstream_task) =
        spawn_early_then_healthy_upstream(b"left").await;
    let running = start_server(streaming_limit_config(upstream_address, "3s")).await;
    let mut abandoned = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    abandoned
        .write_all(
            b"POST /early HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nleft\r\n",
        )
        .await
        .expect("abandoned request prefix");
    timeout(TEST_TIMEOUT, response_written)
        .await
        .expect("cancelled upload upstream response timeout")
        .expect("cancelled upload upstream response signal");
    drop(abandoned);

    let response = send_request(
        running.address,
        "/exact",
        "application/octet-stream",
        b"12345678",
        "",
    )
    .await;
    assert_eq!(response_status(&response), 200);

    let outcome = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("cancelled upload upstream timeout")
        .expect("cancelled upload upstream task");
    assert!(
        !outcome.reused,
        "cancelled upload connection was reused upstream"
    );
    assert!(
        !outcome.first_request.ends_with(b"0\r\n\r\n"),
        "cancelled upload became clean upstream EOS"
    );
    running.wait_for_request_idle().await;
    running.stop().await;
}

#[tokio::test]
async fn opaque_upload_validation_overrides_an_early_upstream_success() {
    let (upstream_address, response_written, upstream_task) = spawn_early_response_upstream().await;
    let running = start_server(streaming_limit_config(upstream_address, "3s")).await;
    let mut downstream = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    downstream
        .write_all(
            b"POST /early HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\naaaaaa\r\n",
        )
        .await
        .expect("first request chunk");
    timeout(TEST_TIMEOUT, response_written)
        .await
        .expect("early upstream response timeout")
        .expect("early upstream response signal");
    downstream
        .write_all(b"6\r\nbbbbbb\r\n0\r\n\r\n")
        .await
        .expect("overflow request chunk");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, downstream.read_to_end(&mut response))
        .await
        .expect("proxy response timeout")
        .expect("proxy response");
    assert_eq!(
        response_status(&response),
        413,
        "{}",
        String::from_utf8_lossy(&response)
    );

    let upstream_request = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("early upstream task timeout")
        .expect("early upstream task");
    assert!(upstream_request
        .windows(b"aaaaaa".len())
        .any(|window| window == b"aaaaaa"));
    assert!(!upstream_request
        .windows(b"bbbbbb".len())
        .any(|window| window == b"bbbbbb"));

    running.stop().await;
}

#[tokio::test]
async fn rejected_early_response_upload_does_not_reuse_its_upstream_connection() {
    let (upstream_address, response_written, upstream_task) =
        spawn_early_then_healthy_upstream(b"aaaaaa").await;
    let running = start_server(streaming_limit_config(upstream_address, "3s")).await;
    let mut downstream = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    downstream
        .write_all(
            b"POST /early HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\naaaaaa\r\n",
        )
        .await
        .expect("first request chunk");
    timeout(TEST_TIMEOUT, response_written)
        .await
        .expect("early upstream response timeout")
        .expect("early upstream response signal");
    downstream
        .write_all(b"6\r\nbbbbbb\r\n0\r\n\r\n")
        .await
        .expect("overflow request chunk");
    let mut rejected = Vec::new();
    timeout(TEST_TIMEOUT, downstream.read_to_end(&mut rejected))
        .await
        .expect("rejected response timeout")
        .expect("rejected response");
    assert_eq!(response_status(&rejected), 413);

    let accepted = send_request(
        running.address,
        "/exact",
        "application/octet-stream",
        b"12345678",
        "",
    )
    .await;
    assert_eq!(response_status(&accepted), 200);

    let outcome = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("connection reuse upstream timeout")
        .expect("connection reuse upstream task");
    assert!(
        !outcome.reused,
        "rejected request connection was reused upstream"
    );
    assert!(
        !outcome.first_request.ends_with(b"0\r\n\r\n"),
        "rejected upload became clean upstream EOS"
    );
    running.wait_for_request_idle().await;
    running.stop().await;
}

#[tokio::test]
async fn upload_deadline_aborts_the_truncated_upstream_connection() {
    let (upstream_address, response_written, upstream_task) =
        spawn_early_then_healthy_upstream(b"held").await;
    let running = start_server(streaming_limit_config(upstream_address, "250ms")).await;
    let mut downstream = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    downstream
        .write_all(
            b"POST /early HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nheld\r\n",
        )
        .await
        .expect("partial request chunk");
    timeout(TEST_TIMEOUT, response_written)
        .await
        .expect("early upstream response timeout")
        .expect("early upstream response signal");

    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, downstream.read_to_end(&mut response))
        .await
        .expect("proxy deadline response timeout")
        .expect("proxy deadline response");
    assert_eq!(
        response_status(&response),
        504,
        "{}",
        String::from_utf8_lossy(&response)
    );

    let accepted = send_request(
        running.address,
        "/exact",
        "application/octet-stream",
        b"12345678",
        "",
    )
    .await;
    assert_eq!(response_status(&accepted), 200);

    let outcome = timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("deadline upstream task timeout")
        .expect("deadline upstream task");
    assert!(
        !outcome.reused,
        "timed-out upload connection was reused upstream"
    );
    assert!(
        !outcome.first_request.ends_with(b"0\r\n\r\n"),
        "timed-out upload became clean upstream EOS"
    );
    running.wait_for_request_idle().await;
    running.stop().await;
}

#[tokio::test]
async fn unconsumed_early_http2_response_does_not_block_other_upstream_streams() {
    let (upstream_address, first_started, upstream_task) = spawn_h2_flow_control_upstream().await;
    let running = start_server(h2_flow_control_config(upstream_address)).await;
    let mut stalled = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    stalled
        .write_all(
            b"POST /h2-stall HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nheld\r\n",
        )
        .await
        .expect("stalled request prefix");
    timeout(TEST_TIMEOUT, first_started)
        .await
        .expect("large h2 response start timeout")
        .expect("large h2 response start signal");
    sleep(Duration::from_millis(250)).await;

    let healthy = timeout(
        Duration::from_secs(1),
        send_request(
            running.address,
            "/h2-health",
            "application/octet-stream",
            b"",
            "",
        ),
    )
    .await
    .expect("large unconsumed response blocked another h2 stream");
    assert_eq!(response_status(&healthy), 200);
    assert_eq!(http_body(&healthy), b"ok");

    drop(stalled);
    running.wait_for_request_idle().await;
    running.stop().await;
    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn early_http2_response_does_not_truncate_a_valid_full_duplex_upload() {
    let (upstream_address, request_started, body_received, upstream_task) =
        spawn_early_h2_upstream().await;
    let running = start_server(h2_streaming_config(upstream_address)).await;
    let mut downstream = timeout(TEST_TIMEOUT, TcpStream::connect(running.address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    downstream
        .write_all(
            b"POST /h2-upload HTTP/1.1\r\nHost: media.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n",
        )
        .await
        .expect("first full-duplex request chunk");
    timeout(TEST_TIMEOUT, request_started)
        .await
        .expect("h2 upstream request timeout")
        .expect("h2 upstream request signal");
    // Give the upstream response headers time to reach Pooler before the rest
    // of the valid request body. Pooler must continue forwarding HTTP/2 DATA.
    sleep(Duration::from_millis(100)).await;
    downstream
        .write_all(b"6\r\nsecond\r\n0\r\n\r\n")
        .await
        .expect("remaining full-duplex request body");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, downstream.read_to_end(&mut response))
        .await
        .expect("full-duplex proxy response timeout")
        .expect("full-duplex proxy response");
    assert_eq!(response_status(&response), 200);
    let body = timeout(TEST_TIMEOUT, body_received)
        .await
        .expect("h2 upstream body timeout")
        .expect("h2 upstream body signal");
    assert_eq!(body, Bytes::from_static(b"firstsecond"));

    running.wait_for_request_idle().await;
    running.stop().await;
    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn semantic_multipart_preserves_wire_bytes_and_rejects_invalid_or_oversize_bodies() {
    let upstream = RecordingUpstream::start(200, b"uploaded").await;
    let running = start_server(multipart_config(upstream.address, 512)).await;
    let content_type = "multipart/form-data; boundary=pooler-media";
    let body = b"--pooler-media\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\ndescribe\r\n--pooler-media\r\nContent-Disposition: form-data; name=\"file\"; filename=\"image.png\"\r\nContent-Type: image/png\r\n\r\nPNG\r\n--pooler-media--\r\n";

    let response = send_request(running.address, "/v1/images/edits", content_type, body, "").await;
    assert_eq!(response_status(&response), 200);
    upstream.wait_for_attempts(1).await;
    let requests = upstream.requests();
    assert_eq!(http_body(&requests[0]), body);
    assert_eq!(
        header_value(&requests[0], "content-type"),
        Some(content_type)
    );

    let malformed =
        b"--pooler-media\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ntruncated";
    let response = send_request(
        running.address,
        "/v1/images/edits",
        content_type,
        malformed,
        "",
    )
    .await;
    assert_eq!(response_status(&response), 400);

    let oversized = vec![b'x'; 513];
    let response = send_request(
        running.address,
        "/v1/images/edits",
        content_type,
        &oversized,
        "",
    )
    .await;
    assert_eq!(response_status(&response), 413);
    sleep(Duration::from_millis(25)).await;
    assert_eq!(
        upstream.attempts(),
        1,
        "rejected multipart reached upstream"
    );

    running.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn native_media_surface_forwards_images_audio_files_batches_and_embeddings() {
    let upstream = RecordingUpstream::start(200, b"ok").await;
    let running = start_server(media_surface_config(upstream.address)).await;
    let operations: [(&str, &str, &str, &[u8]); 7] = [
        (
            "POST",
            "/v1/images/generations",
            "application/json",
            br#"{"prompt":"cat"}"#,
        ),
        (
            "POST",
            "/v1/audio/speech",
            "application/json",
            br#"{"input":"hello"}"#,
        ),
        ("POST", "/v1/files", "application/octet-stream", b"upload"),
        (
            "GET",
            "/v1/files/file-1/content",
            "application/octet-stream",
            b"",
        ),
        (
            "POST",
            "/v1/batches",
            "application/json",
            br#"{"input_file_id":"file-1"}"#,
        ),
        ("GET", "/v1/batches/batch-1", "application/json", b""),
        (
            "POST",
            "/v1/embeddings",
            "application/json",
            br#"{"model":"embed","input":"hello"}"#,
        ),
    ];
    for (method, path, content_type, body) in operations {
        let response =
            send_method_request(running.address, method, path, content_type, body, "").await;
        assert_eq!(response_status(&response), 200, "{method} {path}");
    }

    upstream.wait_for_attempts(operations.len()).await;
    let requests = upstream.requests();
    for ((method, path, _, body), request) in operations.into_iter().zip(requests) {
        assert!(request.starts_with(format!("{method} {path} HTTP/1.1").as_bytes()));
        assert_eq!(http_body(&request), body);
    }
    running.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn opaque_streaming_upload_is_never_retried_after_upstream_consumes_it() {
    let secret_directory = tempfile::tempdir().expect("secret directory");
    let first_secret = write_secret(secret_directory.path(), "first", "media-first");
    let second_secret = write_secret(secret_directory.path(), "second", "media-second");
    let upstream = RecordingUpstream::start(503, b"unavailable").await;
    let running = start_server(opaque_config(
        upstream.address,
        1024,
        Some((&first_secret, &second_secret)),
    ))
    .await;

    let response = send_chunked_request(
        running.address,
        "/v1/images/raw",
        "image/png",
        &[b"streamed-", b"once"],
        "Idempotency-Key: media-upload\r\n",
    )
    .await;
    assert_eq!(response_status(&response), 503);
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        upstream.attempts(),
        1,
        "a consumed streaming upload was replayed"
    );

    running.stop().await;
    upstream.stop().await;
}

fn opaque_config(
    upstream: SocketAddr,
    body_limit: usize,
    account_secrets: Option<(&str, &str)>,
) -> CompiledConfig {
    let pooling = account_secrets.map_or_else(String::new, |(first, second)| {
        format!(
            "accounts:\n  first: {{provider: local, secret: '{first}'}}\n  second: {{provider: local, secret: '{second}'}}\naccount_pools:\n  uploads-pool: {{provider: local, accounts: [first, second]}}\npolicies:\n  uploads:\n    selection: {{strategy: ordered_fallback}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, maximum_upstreams: 1, statuses: [503], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1ms}}\n"
        )
    });
    let target = account_secrets.map_or_else(
        || "local".to_owned(),
        |_| "{provider: local, policy: uploads}".to_owned(),
    );
    compile_yaml(
        "raw-media-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream}}}}}\n{pooling}routes:\n  - id: raw-media\n    listen: local\n    match: {{method: POST, path: /v1/images/raw, content_types: [image/*]}}\n    limits: {{max_request_body_bytes: {body_limit}, max_frame_bytes: 1024}}\n    ingress: {{mode: opaque}}\n    target: {target}\n    response: {{mode: opaque}}\n"
        ),
    )
    .expect("raw media config")
}

fn media_surface_config(upstream: SocketAddr) -> CompiledConfig {
    compile_yaml(
        "media-surface-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream}}}}}\nroutes:\n  - {{id: images, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/images}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [images]}}, response: {{mode: opaque}}}}\n  - {{id: audio, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/audio}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [audio]}}, response: {{mode: opaque}}}}\n  - {{id: files, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/files}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [files]}}, response: {{mode: opaque}}}}\n  - {{id: batches, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/batches}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [batch]}}, response: {{mode: opaque}}}}\n  - {{id: embeddings, listen: local, match: {{method: POST, path: /v1/embeddings}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [text, embeddings]}}, response: {{mode: opaque}}}}\n"
        ),
    )
    .expect("media surface config")
}

fn streaming_limit_config(upstream: SocketAddr, request_timeout: &str) -> CompiledConfig {
    compile_yaml(
        "streaming-limit-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  local:\n    url: http://{upstream}\n    transport: {{request_timeout: {request_timeout}}}\nroutes:\n  - {{id: aggregate, listen: local, match: {{method: POST, path: /aggregate}}, limits: {{max_request_body_bytes: 8, max_frame_bytes: 8}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n  - {{id: frame, listen: local, match: {{method: POST, path: /frame}}, limits: {{max_request_body_bytes: 16, max_frame_bytes: 4}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n  - {{id: exact, listen: local, match: {{method: POST, path: /exact}}, limits: {{max_request_body_bytes: 8, max_frame_bytes: 8}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n  - {{id: early, listen: local, match: {{method: POST, path: /early}}, limits: {{max_request_body_bytes: 8, max_frame_bytes: 8, request_timeout: {request_timeout}}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n"
        ),
    )
    .expect("streaming limit config")
}

fn h2_flow_control_config(upstream: SocketAddr) -> CompiledConfig {
    compile_yaml(
        "h2-flow-control-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  local:\n    transport: {{kind: http, base_url: http://{upstream}, http2: true}}\nroutes:\n  - {{id: h2-stall, listen: local, match: {{method: POST, path: /h2-stall}}, limits: {{max_request_body_bytes: 16, max_response_body_bytes: 67108864, max_frame_bytes: 67108864, max_queue_bytes: 41943040, max_queue_items: 4096, request_timeout: 3s}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n  - {{id: h2-health, listen: local, match: {{method: POST, path: /h2-health}}, limits: {{request_timeout: 3s}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n"
        ),
    )
    .expect("h2 flow-control config")
}

fn h2_streaming_config(upstream: SocketAddr) -> CompiledConfig {
    compile_yaml(
        "h2-streaming-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  local:\n    transport: {{kind: http, base_url: http://{upstream}, http2: true}}\nroutes:\n  - {{id: h2-upload, listen: local, match: {{method: POST, path: /h2-upload}}, limits: {{max_request_body_bytes: 16, max_frame_bytes: 8, request_timeout: 3s}}, ingress: {{mode: opaque}}, target: local, response: {{mode: opaque}}}}\n"
        ),
    )
    .expect("h2 streaming config")
}

fn multipart_config(upstream: SocketAddr, body_limit: usize) -> CompiledConfig {
    compile_yaml(
        "multipart-media-runtime.yaml",
        &format!(
            "version: 2\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream}}}}}\nroutes:\n  - id: multipart-media\n    listen: local\n    match: {{method: POST, path: /v1/images/edits, content_types: [multipart/form-data]}}\n    limits: {{max_request_body_bytes: {body_limit}, max_frame_bytes: {body_limit}}}\n    ingress: {{mode: semantic, decoder: decode.media.multipart}}\n    target: {{provider: local, capabilities: [text, files], codecs: [decode.media.multipart]}}\n    response: {{mode: opaque}}\n"
        ),
    )
    .expect("multipart media config")
}

struct RunningServer {
    server: HttpProxyServer,
    address: SocketAddr,
    runner: JoinHandle<Result<(), HttpProxyServerError>>,
}

impl RunningServer {
    async fn wait_for_request_idle(&self) {
        timeout(TEST_TIMEOUT, async {
            loop {
                let resources = self.server.resource_snapshot();
                if self.server.active() == 0
                    && resources.permits == 0
                    && resources.refresh_leases == 0
                    && resources.temporary_files == 0
                    && resources.secret_material == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "proxy request resources remained active: {:?}",
                self.server.resource_snapshot()
            )
        });
    }

    async fn stop(self) {
        self.server.begin_drain();
        timeout(TEST_TIMEOUT, self.runner)
            .await
            .expect("proxy drain timeout")
            .expect("proxy runner joins")
            .expect("proxy drain succeeds");
        assert!(
            self.server.resource_snapshot().is_zero(),
            "proxy resources remained after drain: {:?}",
            self.server.resource_snapshot()
        );
    }
}

async fn start_server(config: CompiledConfig) -> RunningServer {
    let server = HttpProxyServer::bind(config).await.expect("proxy binds");
    let address = server.listener_addresses()[0]
        .address()
        .parse()
        .expect("proxy address");
    let runner_server = server.clone();
    let runner = tokio::spawn(async move { runner_server.run().await });
    RunningServer {
        server,
        address,
        runner,
    }
}

struct RecordingUpstream {
    address: SocketAddr,
    attempts: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl RecordingUpstream {
    async fn start(status: u16, response_body: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let address = listener.local_addr().expect("upstream address");
        let attempts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_attempts = Arc::clone(&attempts);
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let request = match read_request(&mut stream).await {
                    Ok(request) => request,
                    Err(_) => continue,
                };
                task_attempts.fetch_add(1, Ordering::SeqCst);
                task_requests.lock().expect("request lock").push(request);
                let reason = match status {
                    200 => "OK",
                    201 => "Created",
                    503 => "Service Unavailable",
                    _ => "Response",
                };
                let headers = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_body.len()
                );
                if stream.write_all(headers.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(response_body).await;
                }
            }
        });
        Self {
            address,
            attempts,
            requests,
            task,
        }
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("request lock").clone()
    }

    async fn wait_for_attempts(&self, expected: usize) {
        timeout(TEST_TIMEOUT, async {
            while self.attempts() < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("upstream attempt timeout");
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn spawn_h2_flow_control_upstream() -> (SocketAddr, oneshot::Receiver<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("h2 flow-control upstream binds");
    let address = listener.local_addr().expect("h2 flow-control address");
    let (first_started_tx, first_started_rx) = oneshot::channel();
    let first_started_tx = Arc::new(Mutex::new(Some(first_started_tx)));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("h2 flow-control accepts");
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let first_started_tx = Arc::clone(&first_started_tx);
            async move {
                match request.uri().path() {
                    "/h2-stall" => {
                        if let Some(sender) = first_started_tx.lock().expect("start lock").take() {
                            let _ = sender.send(());
                        }
                        tokio::spawn(async move {
                            let _ = request.into_body().collect().await;
                        });
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from(vec![b'x'; 32 * 1024 * 1024])))
                                .expect("large h2 response"),
                        )
                    }
                    "/h2-health" => Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-length", "2")
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .expect("healthy h2 response"),
                    ),
                    path => panic!("unexpected h2 path: {path}"),
                }
            }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("h2 flow-control connection");
    });
    (address, first_started_rx, task)
}

async fn spawn_early_h2_upstream() -> (
    SocketAddr,
    oneshot::Receiver<()>,
    oneshot::Receiver<Bytes>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("h2 full-duplex upstream binds");
    let address = listener.local_addr().expect("h2 full-duplex address");
    let (request_started_tx, request_started_rx) = oneshot::channel();
    let request_started_tx = Arc::new(Mutex::new(Some(request_started_tx)));
    let (body_received_tx, body_received_rx) = oneshot::channel();
    let body_received_tx = Arc::new(Mutex::new(Some(body_received_tx)));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("h2 upstream accepts");
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let request_started_tx = Arc::clone(&request_started_tx);
            let body_received_tx = Arc::clone(&body_received_tx);
            async move {
                if let Some(sender) = request_started_tx.lock().expect("start lock").take() {
                    let _ = sender.send(());
                }
                tokio::spawn(async move {
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .expect("h2 request body")
                        .to_bytes();
                    if let Some(sender) = body_received_tx.lock().expect("body lock").take() {
                        let _ = sender.send(body);
                    }
                });
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(200)
                        .header("content-length", "2")
                        .body(Full::new(Bytes::from_static(b"ok")))
                        .expect("h2 early response"),
                )
            }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("h2 upstream connection");
    });
    (address, request_started_rx, body_received_rx, task)
}

struct EarlyUpstreamOutcome {
    reused: bool,
    first_request: Vec<u8>,
}

async fn spawn_early_then_healthy_upstream(
    marker: &'static [u8],
) -> (
    SocketAddr,
    oneshot::Receiver<()>,
    JoinHandle<EarlyUpstreamOutcome>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("connection-reuse upstream binds");
    let address = listener.local_addr().expect("connection-reuse address");
    let (response_written, response_observed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first upstream accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request.windows(marker.len()).any(|window| window == marker) {
            let read = first.read(&mut buffer).await.expect("first upstream read");
            assert_ne!(read, 0, "first upstream closed before request body");
            request.extend_from_slice(&buffer[..read]);
        }
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
            .await
            .expect("first upstream response");
        let _ = response_written.send(());
        while !request.ends_with(b"0\r\n\r\n") {
            let read = first.read(&mut buffer).await.expect("first upload drain");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }

        let reused_request = timeout(Duration::from_millis(250), read_request(&mut first)).await;
        let (reused, mut second) = match reused_request {
            Ok(Ok(request)) if !request.is_empty() => (true, first),
            _ => {
                let (second, _) = listener.accept().await.expect("second upstream accept");
                (false, second)
            }
        };
        if !reused {
            let request = read_request(&mut second)
                .await
                .expect("second upstream request");
            assert!(request.starts_with(b"POST /exact HTTP/1.1"));
        }
        second
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("second upstream response");
        EarlyUpstreamOutcome {
            reused,
            first_request: request,
        }
    });
    (address, response_observed, task)
}

async fn spawn_early_response_upstream() -> (SocketAddr, oneshot::Receiver<()>, JoinHandle<Vec<u8>>)
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("early-response upstream binds");
    let address = listener.local_addr().expect("early-response address");
    let (response_written, response_observed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("early-response accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request
            .windows(b"aaaaaa".len())
            .any(|window| window == b"aaaaaa")
            && !request
                .windows(b"held".len())
                .any(|window| window == b"held")
        {
            let read = stream.read(&mut buffer).await.expect("early request read");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
            .await
            .expect("early response write");
        let _ = response_written.send(());
        let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut request)).await;
        request
    });
    (address, response_observed, task)
}

fn write_secret(directory: &Path, name: &str, value: &str) -> String {
    let path = directory.join(name);
    std::fs::write(&path, value).expect("secret file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secret file permissions");
    }
    format!("file:{}", path.display())
}

async fn send_request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &str,
) -> Vec<u8> {
    send_method_request(address, "POST", path, content_type, body, extra_headers).await
}

async fn send_method_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &str,
) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: media.test\r\nContent-Type: {content_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("request headers");
    stream.write_all(body).await.expect("request body");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("proxy response timeout")
        .expect("proxy response");
    response
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let body_start = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    if header_value(&bytes[..body_start], "transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        while !bytes[body_start..].ends_with(b"0\r\n\r\n") {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        return Ok(bytes);
    }
    let content_length = header_value(&bytes[..body_start], "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < body_start.saturating_add(content_length) {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

async fn read_http_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    let body_start = timeout(TEST_TIMEOUT, async {
        loop {
            let read = stream.read(&mut buffer).await.expect("response read");
            assert_ne!(read, 0, "connection closed before response headers");
            response.extend_from_slice(&buffer[..read]);
            if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        }
    })
    .await
    .expect("response header timeout");
    let content_length = header_value(&response[..body_start], "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .expect("response content length");
    timeout(TEST_TIMEOUT, async {
        while response.len() < body_start.saturating_add(content_length) {
            let read = stream.read(&mut buffer).await.expect("response body read");
            assert_ne!(read, 0, "connection closed before response body");
            response.extend_from_slice(&buffer[..read]);
        }
    })
    .await
    .expect("response body timeout");
    response
}

fn response_status(response: &[u8]) -> u16 {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("response status line");
    std::str::from_utf8(&response[..line_end])
        .expect("response status UTF-8")
        .split_whitespace()
        .nth(1)
        .expect("response status")
        .parse()
        .expect("numeric response status")
}

async fn send_chunked_request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    chunks: &[&[u8]],
    extra_headers: &str,
) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("proxy connect timeout")
        .expect("proxy connection");
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: media.test\r\nContent-Type: {content_type}\r\n{extra_headers}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("chunked request headers");
    for chunk in chunks {
        stream
            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
            .await
            .expect("chunk size");
        stream.write_all(chunk).await.expect("request chunk");
        stream.write_all(b"\r\n").await.expect("chunk terminator");
    }
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .expect("final request chunk");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("proxy response timeout")
        .expect("proxy response");
    response
}

fn http_body(message: &[u8]) -> &[u8] {
    let body_start = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP header terminator")
        + 4;
    &message[body_start..]
}

fn header_value<'a>(message: &'a [u8], expected: &str) -> Option<&'a str> {
    let header_end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(message.len(), |position| position);
    message[..header_end]
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let separator = line.iter().position(|byte| *byte == b':')?;
            let name = std::str::from_utf8(&line[..separator]).ok()?;
            if !name.eq_ignore_ascii_case(expected) {
                return None;
            }
            std::str::from_utf8(&line[separator + 1..])
                .ok()
                .map(str::trim)
        })
}
