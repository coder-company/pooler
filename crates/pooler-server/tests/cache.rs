use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use pooler_config::compile_yaml;
use pooler_server::HttpProxyServer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_BODY: &[u8] = br#"{"model":"gpt-test","prompt":"same"}"#;

#[tokio::test]
async fn enabled_cache_replays_only_a_completed_response() {
    let (upstream, requests, upstream_task) = spawn_upstream(Duration::ZERO).await;
    let (server, address, runner) = start_server(upstream, true).await;

    let first = http_request(address, REQUEST_BODY, true).await;
    let second = http_request(address, REQUEST_BODY, true).await;
    assert_eq!(first, b"cached response");
    assert_eq!(second, b"cached response");
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    shutdown(server, runner).await;
    upstream_task.abort();
}

#[tokio::test]
async fn coalescing_waiters_receive_the_buffered_result_without_stream_fanout() {
    let (upstream, requests, upstream_task) = spawn_upstream(Duration::from_millis(100)).await;
    let (server, address, runner) = start_server(upstream, true).await;

    let first = tokio::spawn(http_request(address, REQUEST_BODY, true));
    let second = tokio::spawn(http_request(address, REQUEST_BODY, true));
    assert_eq!(first.await.expect("first request"), b"cached response");
    assert_eq!(second.await.expect("second request"), b"cached response");
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    shutdown(server, runner).await;
    upstream_task.abort();
}

#[tokio::test]
async fn cache_remains_disabled_without_explicit_enablement() {
    let (upstream, requests, upstream_task) = spawn_upstream(Duration::ZERO).await;
    let (server, address, runner) = start_server(upstream, false).await;

    let first = http_request(address, REQUEST_BODY, true).await;
    let second = http_request(address, REQUEST_BODY, true).await;
    assert_eq!(first, b"cached response");
    assert_eq!(second, b"cached response");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    shutdown(server, runner).await;
    upstream_task.abort();
}

#[tokio::test]
async fn post_without_idempotency_key_is_not_cached() {
    let (upstream, requests, upstream_task) = spawn_upstream(Duration::ZERO).await;
    let (server, address, runner) = start_server(upstream, true).await;

    let first = http_request(address, REQUEST_BODY, false).await;
    let second = http_request(address, REQUEST_BODY, false).await;
    assert_eq!(first, b"cached response");
    assert_eq!(second, b"cached response");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    shutdown(server, runner).await;
    upstream_task.abort();
}

async fn start_server(
    upstream: std::net::SocketAddr,
    enabled: bool,
) -> (
    HttpProxyServer,
    std::net::SocketAddr,
    JoinHandle<Result<(), pooler_server::HttpProxyServerError>>,
) {
    let cache = if enabled {
        "    cache: {enabled: true, ttl: 10s, max_entries: 4, max_bytes: 1KiB, coalesce: true}\n"
    } else {
        ""
    };
    let config_text = format!(
        "version: 2\nlisteners:\n  local:\n    bind: 127.0.0.1:0\nupstreams:\n  local:\n    url: http://{upstream}\nroutes:\n  - id: cached\n    listen: local\n    match: {{method: POST, path: /cache}}\n    ingress: {{mode: patch}}\n    response: {{mode: opaque}}\n{cache}    target: local\n"
    );
    let config = compile_yaml("cache-runtime.yaml", &config_text).expect("cache config");
    let server = HttpProxyServer::bind(config).await.expect("server binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("listener address")
        .address()
        .parse()
        .expect("listener address parses");
    let runner_server = server.clone();
    let runner = tokio::spawn(async move { runner_server.run().await });
    (server, address, runner)
}

async fn shutdown(
    server: HttpProxyServer,
    runner: JoinHandle<Result<(), pooler_server::HttpProxyServerError>>,
) {
    server.begin_drain();
    timeout(TEST_TIMEOUT, runner)
        .await
        .expect("server drains")
        .expect("server joins")
        .expect("server succeeds");
}

async fn http_request(
    address: std::net::SocketAddr,
    body: &[u8],
    idempotency_key: bool,
) -> Vec<u8> {
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .expect("connect timeout")
        .expect("connect");
    let idempotency_key = if idempotency_key {
        "Idempotency-Key: cache-test\r\n"
    } else {
        ""
    };
    let request = format!(
        "POST /cache HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{idempotency_key}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("request headers");
    stream.write_all(body).await.expect("request body");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("response read");
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers");
    let headers = &response[..separator];
    let content_length = headers
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            let (name, value) = (&line[..colon], &line[colon + 1..]);
            (name.eq_ignore_ascii_case(b"content-length"))
                .then(|| {
                    std::str::from_utf8(value)
                        .ok()?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .flatten()
        })
        .expect("content length");
    let body_start = separator + 4;
    response[body_start..body_start + content_length].to_vec()
}

async fn spawn_upstream(
    delay: Duration,
) -> (std::net::SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let requests = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("upstream accepts");
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let _ = read_request(&mut stream).await;
                count.fetch_add(1, Ordering::SeqCst);
                sleep(delay).await;
                let body = b"cached response";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    (address, requests, task)
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
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
    let content_length = bytes[..body_start]
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            let (name, value) = (&line[..colon], &line[colon + 1..]);
            (name.eq_ignore_ascii_case(b"content-length"))
                .then(|| {
                    std::str::from_utf8(value)
                        .ok()?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .flatten()
        })
        .unwrap_or(0);
    while bytes.len() < body_start + content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}
