use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use pooler_config::{compile_yaml, CompiledConfig};
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
            "accounts:\n  first: {{provider: local, secret: '{first}'}}\n  second: {{provider: local, secret: '{second}'}}\npolicies:\n  uploads:\n    selection: {{strategy: ordered_fallback, accounts: [first, second]}}\n    retry: {{maximum_attempts: 2, maximum_credentials: 2, maximum_providers: 1, statuses: [503], before_commit_only: true, base_delay: 0ms, maximum_delay: 1ms, maximum_total_delay: 1ms}}\n"
        )
    });
    let target = account_secrets.map_or_else(
        || "local".to_owned(),
        |_| "{provider: local, policy: uploads}".to_owned(),
    );
    compile_yaml(
        "raw-media-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream}}}}}\n{pooling}routes:\n  - id: raw-media\n    listen: local\n    match: {{method: POST, path: /v1/images/raw, content_types: [image/*]}}\n    limits: {{max_request_body_bytes: {body_limit}, max_frame_bytes: 1024}}\n    ingress: {{mode: opaque}}\n    target: {target}\n    response: {{mode: opaque}}\n"
        ),
    )
    .expect("raw media config")
}

fn media_surface_config(upstream: SocketAddr) -> CompiledConfig {
    compile_yaml(
        "media-surface-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream}}}}}\nroutes:\n  - {{id: images, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/images}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [images]}}, response: {{mode: opaque}}}}\n  - {{id: audio, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/audio}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [audio]}}, response: {{mode: opaque}}}}\n  - {{id: files, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/files}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [files]}}, response: {{mode: opaque}}}}\n  - {{id: batches, listen: local, match: {{methods: [GET, POST, DELETE], path_prefix: /v1/batches}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [batch]}}, response: {{mode: opaque}}}}\n  - {{id: embeddings, listen: local, match: {{method: POST, path: /v1/embeddings}}, ingress: {{mode: opaque}}, target: {{provider: local, capabilities: [text, embeddings]}}, response: {{mode: opaque}}}}\n"
        ),
    )
    .expect("media surface config")
}

fn multipart_config(upstream: SocketAddr, body_limit: usize) -> CompiledConfig {
    compile_yaml(
        "multipart-media-runtime.yaml",
        &format!(
            "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream}}}}}\nroutes:\n  - id: multipart-media\n    listen: local\n    match: {{method: POST, path: /v1/images/edits, content_types: [multipart/form-data]}}\n    limits: {{max_request_body_bytes: {body_limit}, max_frame_bytes: {body_limit}}}\n    ingress: {{mode: semantic, decoder: decode.media.multipart}}\n    target: {{provider: local, capabilities: [text, files], codecs: [decode.media.multipart]}}\n    response: {{mode: opaque}}\n"
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
    async fn stop(self) {
        self.server.begin_drain();
        timeout(TEST_TIMEOUT, self.runner)
            .await
            .expect("proxy drain timeout")
            .expect("proxy runner joins")
            .expect("proxy drain succeeds");
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
