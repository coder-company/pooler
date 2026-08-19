//! Concrete Hyper listener runtime for the opaque HTTP proxy.

use std::{
    convert::Infallible,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use hyper::{body::Incoming, http::Request, service::service_fn};
use hyper_util::rt::TokioIo;
use pooler_config::CompiledConfig;
use pooler_http::{DrainError, HttpProxy, ProxyError};
use thiserror::Error;
use tokio::{
    net::{TcpListener, UnixListener},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

const FORCE_CANCEL_GRACE: Duration = Duration::from_secs(1);

/// A listener's concrete address after binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerAddress {
    id: Arc<str>,
    address: Arc<str>,
}

impl ListenerAddress {
    /// Stable listener ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Display form of the assigned TCP address or Unix path.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Errors raised while binding or running concrete HTTP listeners.
#[derive(Debug, Error)]
pub enum HttpProxyServerError {
    /// A configured listener failed to bind.
    #[error("failed to bind listener `{listener}`: {source}")]
    Bind {
        listener: String,
        #[source]
        source: io::Error,
    },
    /// Proxy transport setup failed.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    /// Graceful drain exceeded its bound.
    #[error(transparent)]
    Drain(#[from] DrainError),
    /// A listener task failed unexpectedly.
    #[error("listener `{listener}` failed: {message}")]
    Listener { listener: String, message: String },
    /// `run` already consumed the bound sockets.
    #[error("HTTP proxy server is already running")]
    AlreadyRunning,
}

enum BoundListener {
    Tcp {
        id: Arc<str>,
        listener: TcpListener,
        proxy: Arc<HttpProxy>,
    },
    Unix {
        id: Arc<str>,
        listener: UnixListener,
        path: UnixSocketPath,
        proxy: Arc<HttpProxy>,
    },
}

struct UnixSocketPath(PathBuf);

impl Drop for UnixSocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct RuntimeState {
    listeners: Mutex<Option<Vec<BoundListener>>>,
    proxies: Vec<Arc<HttpProxy>>,
    cancellation: CancellationToken,
}

/// A concrete HTTP/1 listener set serving every compiled listener.
#[derive(Clone)]
pub struct HttpProxyServer {
    state: Arc<RuntimeState>,
    addresses: Arc<Vec<ListenerAddress>>,
}

impl std::fmt::Debug for HttpProxyServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProxyServer")
            .field("listeners", &self.addresses)
            .field("active", &self.active())
            .field("draining", &self.is_draining())
            .finish()
    }
}

impl HttpProxyServer {
    /// Bind all listeners before accepting any downstream connection.
    pub async fn bind(config: CompiledConfig) -> Result<Self, HttpProxyServerError> {
        let config = Arc::new(config);
        let mut listeners = Vec::with_capacity(config.listeners().len());
        let mut proxies = Vec::with_capacity(config.listeners().len());
        let mut addresses = Vec::with_capacity(config.listeners().len());

        for plan in config.listeners().values() {
            let id: Arc<str> = Arc::from(plan.id());
            let proxy = Arc::new(HttpProxy::new(Arc::clone(&config), Arc::clone(&id))?);
            let bind = plan.bind();
            if bind.starts_with('/') || bind.starts_with("unix:") {
                let path = bind.strip_prefix("unix:").unwrap_or(bind);
                let listener =
                    UnixListener::bind(path).map_err(|source| HttpProxyServerError::Bind {
                        listener: bind.to_owned(),
                        source,
                    })?;
                listeners.push(BoundListener::Unix {
                    id: Arc::clone(&id),
                    listener,
                    path: UnixSocketPath(PathBuf::from(path)),
                    proxy: Arc::clone(&proxy),
                });
                addresses.push(ListenerAddress {
                    id,
                    address: Arc::from(path),
                });
            } else {
                let listener =
                    TcpListener::bind(bind)
                        .await
                        .map_err(|source| HttpProxyServerError::Bind {
                            listener: bind.to_owned(),
                            source,
                        })?;
                let address =
                    listener
                        .local_addr()
                        .map_err(|source| HttpProxyServerError::Bind {
                            listener: bind.to_owned(),
                            source,
                        })?;
                listeners.push(BoundListener::Tcp {
                    id: Arc::clone(&id),
                    listener,
                    proxy: Arc::clone(&proxy),
                });
                addresses.push(ListenerAddress {
                    id,
                    address: Arc::from(address.to_string()),
                });
            }
            proxies.push(proxy);
        }

        Ok(Self {
            state: Arc::new(RuntimeState {
                listeners: Mutex::new(Some(listeners)),
                proxies,
                cancellation: CancellationToken::new(),
            }),
            addresses: Arc::new(addresses),
        })
    }

    /// Addresses assigned while binding, in compiled listener order.
    #[must_use]
    pub fn listener_addresses(&self) -> &[ListenerAddress] {
        self.addresses.as_slice()
    }

    /// Number of active requests across listeners.
    #[must_use]
    pub fn active(&self) -> usize {
        self.state
            .proxies
            .iter()
            .map(|proxy| proxy.drain_controller().active())
            .sum()
    }

    /// Whether shutdown has begun on any listener.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.state
            .proxies
            .iter()
            .any(|proxy| proxy.drain_controller().is_draining())
    }

    /// Run all accept loops until graceful drain is requested.
    pub async fn run(&self) -> Result<(), HttpProxyServerError> {
        self.run_with_drain_timeout(Duration::from_secs(30)).await
    }

    async fn run_with_drain_timeout(
        &self,
        drain_timeout: Duration,
    ) -> Result<(), HttpProxyServerError> {
        let listeners = self
            .state
            .listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(HttpProxyServerError::AlreadyRunning)?;
        let mut tasks = JoinSet::new();
        for listener in listeners {
            let cancellation = self.state.cancellation.clone();
            tasks.spawn(async move { accept_loop(listener, cancellation).await });
        }

        loop {
            tokio::select! {
                _ = self.state.cancellation.cancelled() => break,
                result = tasks.join_next() => {
                    match result {
                        Some(Ok(Ok(()))) => {}
                        Some(Ok(Err(error))) => {
                            self.begin_drain();
                            return Err(error);
                        }
                        Some(Err(error)) => {
                            self.begin_drain();
                            return Err(HttpProxyServerError::Listener {
                                listener: "unknown".to_owned(),
                                message: error.to_string(),
                            });
                        }
                        None => break,
                    }
                }
            }
        }

        self.begin_drain();
        let drain_result = self.drain(drain_timeout).await;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => {
                    return Err(HttpProxyServerError::Listener {
                        listener: "unknown".to_owned(),
                        message: error.to_string(),
                    });
                }
            }
        }
        drain_result
    }

    /// Begin graceful drain and wait for all listener requests to finish.
    pub async fn drain(&self, timeout: Duration) -> Result<(), HttpProxyServerError> {
        self.begin_drain();
        let deadline = tokio::time::Instant::now() + timeout;
        for proxy in &self.state.proxies {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Err(error) = proxy.drain(remaining).await {
                for proxy in &self.state.proxies {
                    proxy.cancel_active();
                }
                let cleanup_deadline = tokio::time::Instant::now() + FORCE_CANCEL_GRACE;
                for proxy in &self.state.proxies {
                    let remaining =
                        cleanup_deadline.saturating_duration_since(tokio::time::Instant::now());
                    proxy.drain(remaining).await?;
                }
                return Err(error.into());
            }
        }
        Ok(())
    }

    /// Signal all listeners to stop accepting connections.
    pub fn begin_drain(&self) {
        for proxy in &self.state.proxies {
            proxy.begin_drain();
        }
        self.state.cancellation.cancel();
    }

    /// Cancellation token used by process lifecycle integration.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.state.cancellation.clone()
    }
}

async fn accept_loop(
    listener: BoundListener,
    cancellation: CancellationToken,
) -> Result<(), HttpProxyServerError> {
    match listener {
        BoundListener::Tcp {
            id,
            listener,
            proxy,
        } => {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, peer) = result.map_err(|source| HttpProxyServerError::Listener {
                            listener: id.to_string(),
                            message: source.to_string(),
                        })?;
                        let proxy = Arc::clone(&proxy);
                        let connection_id = Arc::clone(&id);
                        let cancellation = cancellation.clone();
                        connections.spawn(async move {
                            serve_connection(TokioIo::new(stream), connection_id, proxy, cancellation).await;
                        });
                        debug!(listener = %id, ?peer, "accepted HTTP connection");
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = result {
                            debug!(listener = %id, %error, "HTTP connection task failed");
                        }
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    debug!(listener = %id, %error, "HTTP connection task failed during drain");
                }
            }
        }
        BoundListener::Unix {
            id,
            listener,
            path: _path,
            proxy,
        } => {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    result = listener.accept() => {
                        let (stream, _) = result.map_err(|source| HttpProxyServerError::Listener {
                            listener: id.to_string(),
                            message: source.to_string(),
                        })?;
                        let proxy = Arc::clone(&proxy);
                        let id = Arc::clone(&id);
                        let cancellation = cancellation.clone();
                        connections.spawn(async move {
                            serve_connection(TokioIo::new(stream), id, proxy, cancellation).await;
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = result {
                            debug!(listener = %id, %error, "HTTP connection task failed");
                        }
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    debug!(listener = %id, %error, "HTTP connection task failed during drain");
                }
            }
        }
    }
    Ok(())
}

async fn serve_connection<I>(
    io: TokioIo<I>,
    listener_id: Arc<str>,
    proxy: Arc<HttpProxy>,
    cancellation: CancellationToken,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let proxy = Arc::clone(&proxy);
        async move { Ok::<_, Infallible>(proxy.handle(request).await) }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service);
    tokio::pin!(connection);

    tokio::select! {
        result = &mut connection => {
            if let Err(error) = result {
                debug!(listener = %listener_id, %error, "HTTP connection closed with an error");
            }
        }
        _ = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();
            if let Err(error) = connection.await {
                debug!(listener = %listener_id, %error, "HTTP connection drained with an error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{sleep, Duration},
    };

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct TestSecret {
        path: PathBuf,
    }

    impl TestSecret {
        fn new(value: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "pooler-http-runtime-secret-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, value).expect("test secret writes");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("test secret permissions");
            }
            Self { path }
        }

        fn reference(&self) -> String {
            format!("file:{}", self.path.display())
        }
    }

    impl Drop for TestSecret {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn spawn_one_shot_upstream(
        body: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let address = listener.local_addr().expect("upstream address available");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("upstream accepts");
            let request = read_request(&mut stream)
                .await
                .expect("upstream request bytes");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .await
                .expect("upstream response headers");
            stream
                .write_all(body)
                .await
                .expect("upstream response body");
            request
        });
        (address, task)
    }

    async fn send_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        stream
            .write_all(request)
            .await
            .expect("downstream request bytes");
        tokio::time::timeout(TEST_TIMEOUT, read_response(&mut stream))
            .await
            .expect("downstream response arrives before timeout")
            .expect("downstream response bytes")
    }

    async fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before HTTP headers",
                ));
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(bytes);
            }
        }
    }

    async fn read_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = read_headers(stream).await?;
        let header_length = header_end(&bytes).map_or(bytes.len(), |index| index + 4);
        let body_length = content_length(&bytes[..header_length]).unwrap_or_default();
        let request_length = header_length + body_length;
        while bytes.len() < request_length {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before request body",
                ));
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        bytes.truncate(request_length);
        Ok(bytes)
    }

    async fn read_response(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = header_end(&bytes) else {
                continue;
            };
            let Some(content_length) = content_length(&bytes[..header_end]) else {
                continue;
            };
            let response_end = header_end + 4 + content_length;
            if bytes.len() >= response_end {
                bytes.truncate(response_end);
                return Ok(bytes);
            }
        }
    }

    fn header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &[u8]) -> Option<usize> {
        String::from_utf8_lossy(headers).lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
    }

    fn status(response: &[u8]) -> u16 {
        String::from_utf8_lossy(response)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap_or_default()
    }

    fn response_body(response: &[u8]) -> &[u8] {
        let Some(header_end) = header_end(response) else {
            return &[];
        };
        &response[header_end + 4..]
    }

    fn has_header(request: &[u8], expected: &str) -> bool {
        String::from_utf8_lossy(request).lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case(expected))
        })
    }

    fn listener_address(server: &HttpProxyServer, id: &str) -> SocketAddr {
        server
            .listener_addresses()
            .iter()
            .find(|listener| listener.id() == id)
            .unwrap_or_else(|| panic!("listener `{id}` is not bound"))
            .address()
            .parse()
            .expect("ephemeral listener address")
    }

    async fn wait_for_active(server: &HttpProxyServer, expected: usize) {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if server.active() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("proxy reaches expected active count");
    }

    async fn stop_server(
        server: &HttpProxyServer,
        runner: tokio::task::JoinHandle<Result<(), HttpProxyServerError>>,
    ) {
        server.drain(TEST_TIMEOUT).await.expect("proxy drains");
        assert_eq!(server.active(), 0);
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
    }

    #[tokio::test]
    async fn forwards_opaque_bytes_across_ephemeral_listeners() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream address available");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.expect("request bytes");
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Upstream: yes\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .expect("response bytes");
            request
        });

        let config = pooler_config::compile_yaml(
            "e2e.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: opaque\n    listen: local\n    match: {{method: GET, path: /proxy}}\n    target: local\n"
            ),
        )
        .expect("proxy config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let downstream_address: SocketAddr = server.listener_addresses()[0]
            .address()
            .parse()
            .expect("ephemeral listener address");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        // Give the accept loop a scheduling turn before connecting. TCP would
        // also queue the connection, but this keeps the test deterministic on
        // slower CI workers.
        sleep(Duration::from_millis(1)).await;
        let mut downstream = TcpStream::connect(downstream_address)
            .await
            .expect("downstream connects");
        downstream
            .write_all(
                b"GET /proxy?opaque=true HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("request bytes");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !response.ends_with(b"hello") {
            let read = tokio::time::timeout(Duration::from_secs(5), downstream.read(&mut buffer))
                .await
                .expect("response arrives before timeout")
                .expect("response bytes");
            assert_ne!(
                read,
                0,
                "response closed early: {}",
                String::from_utf8_lossy(&response)
            );
            response.extend_from_slice(&buffer[..read]);
        }
        drop(downstream);

        server
            .drain(Duration::from_secs(5))
            .await
            .expect("proxy drains");
        runner
            .await
            .expect("proxy task does not panic")
            .expect("proxy task succeeds");
        let upstream_request = upstream.await.expect("upstream task does not panic");

        assert!(upstream_request.starts_with(b"GET /proxy?opaque=true HTTP/1.1\r\n"));
        assert!(!upstream_request
            .windows(b"connection:".len())
            .any(|window| window.eq_ignore_ascii_case(b"connection:")));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"hello"));
        assert!(response
            .windows(b"x-upstream: yes".len())
            .any(|window| { window.eq_ignore_ascii_case(b"x-upstream: yes") }));
    }

    #[tokio::test]
    async fn dispatches_mixed_routes_on_one_listener() {
        let (first_address, first_upstream) = spawn_one_shot_upstream(b"first").await;
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"second").await;
        let config = pooler_config::compile_yaml(
            "mixed.yaml",
            &format!(
                "version: 1\nlisteners: {{shared: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  first: {{url: http://{first_address}}}\n  second: {{url: http://{second_address}}}\nroutes:\n  - id: first\n    listen: shared\n    match: {{path: /first}}\n    target: first\n  - id: second\n    listen: shared\n    match: {{path: /second}}\n    target: second\n"
            ),
        )
        .expect("mixed config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "shared");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let first = send_request(address, b"GET /first HTTP/1.1\r\nHost: test\r\n\r\n").await;
        let second = send_request(address, b"GET /second HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&first), b"first");
        assert_eq!(response_body(&second), b"second");
        assert!(first_upstream
            .await
            .expect("first upstream")
            .starts_with(b"GET /first "));
        assert!(second_upstream
            .await
            .expect("second upstream")
            .starts_with(b"GET /second "));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn serves_same_path_on_two_independent_listeners() {
        let (first_address, first_upstream) = spawn_one_shot_upstream(b"listener-a").await;
        let (second_address, second_upstream) = spawn_one_shot_upstream(b"listener-b").await;
        let config = pooler_config::compile_yaml(
            "listeners.yaml",
            &format!(
                "version: 1\nlisteners:\n  a: {{bind: 127.0.0.1:0}}\n  b: {{bind: 127.0.0.1:0}}\nupstreams:\n  a: {{url: http://{first_address}}}\n  b: {{url: http://{second_address}}}\nroutes:\n  - {{id: a, listen: a, match: {{path: /same}}, target: a}}\n  - {{id: b, listen: b, match: {{path: /same}}, target: b}}\n"
            ),
        )
        .expect("multi-listener config");
        let server = HttpProxyServer::bind(config).await.expect("listeners bind");
        let first_listener = listener_address(&server, "a");
        let second_listener = listener_address(&server, "b");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let first = send_request(first_listener, b"GET /same HTTP/1.1\r\nHost: test\r\n\r\n").await;
        let second =
            send_request(second_listener, b"GET /same HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(response_body(&first), b"listener-a");
        assert_eq!(response_body(&second), b"listener-b");
        assert!(first_upstream
            .await
            .expect("first upstream")
            .starts_with(b"GET /same "));
        assert!(second_upstream
            .await
            .expect("second upstream")
            .starts_with(b"GET /same "));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn bearer_auth_rejects_before_upstream_and_is_not_forwarded() {
        let secret = TestSecret::new("correct-token\n");
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"accepted").await;
        let config = pooler_config::compile_yaml(
            "auth.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: protected\n    listen: local\n    match: {{path: /protected}}\n    downstream_auth: {{secret: {}}}\n    target: local\n",
                secret.reference()
            ),
        )
        .expect("auth config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let rejected = send_request(
            address,
            b"GET /protected HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer wrong\r\n\r\n",
        )
        .await;
        assert_eq!(status(&rejected), 401);
        let accepted = send_request(
            address,
            b"GET /protected HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer correct-token\r\n\r\n",
        )
        .await;
        assert_eq!(status(&accepted), 200);
        let upstream_request = upstream.await.expect("upstream task");
        assert!(!has_header(&upstream_request, "authorization"));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn rejects_declared_oversized_body_before_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let config = pooler_config::compile_yaml(
            "limit.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: limited\n    listen: local\n    match: {{method: POST, path: /limited}}\n    limits: {{max_request_body_bytes: 3}}\n    target: local\n  - id: expanded\n    listen: local\n    match: {{method: POST, path: /expanded}}\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /x, value: \"1234567890123456789012345678901234567890\"}}\n    limits: {{max_request_body_bytes: 16}}\n    target: local\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("limit config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(
            address,
            b"POST /limited HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nhello",
        )
        .await;
        assert_eq!(status(&response), 413);
        let encoded = send_request(
            address,
            b"POST /limited HTTP/1.1\r\nHost: test\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx",
        )
        .await;
        assert_eq!(status(&encoded), 415);
        let repeated_encoding = send_request(
            address,
            b"POST /limited HTTP/1.1\r\nHost: test\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx",
        )
        .await;
        assert_eq!(status(&repeated_encoding), 415);
        let expanded = send_request(
            address,
            b"POST /expanded HTTP/1.1\r\nHost: test\r\nContent-Length: 7\r\n\r\n{\"x\":0}",
        )
        .await;
        assert_eq!(status(&expanded), 413);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn terminates_oversized_upstream_response() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"hello").await;
        let config = pooler_config::compile_yaml(
            "response-limit.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: limited\n    listen: local\n    limits: {{max_response_body_bytes: 3}}\n    target: local\n"
            ),
        )
        .expect("response limit config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        let response = send_request(address, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(status(&response), 502);
        assert_ne!(response_body(&response), b"hello");
        upstream.await.expect("upstream task");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn downstream_disconnect_releases_active_request() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            read_headers(&mut stream).await.expect("upstream request");
            let mut byte = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
                .await
                .expect("upstream is canceled")
                .expect("upstream read")
        });
        let config = pooler_config::compile_yaml(
            "cancel.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes: [{{id: cancel, listen: local, target: local}}]\n"
            ),
        )
        .expect("cancel config compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let mut downstream = TcpStream::connect(address)
            .await
            .expect("downstream connects");
        downstream
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .expect("request writes");
        wait_for_active(&server, 1).await;
        drop(downstream);

        assert_eq!(upstream.await.expect("upstream task"), 0);
        tokio::time::timeout(TEST_TIMEOUT, async {
            while server.active() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("active request releases");
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn lifecycle_cancellation_force_drains_pending_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("upstream accepts");
            read_headers(&mut stream).await.expect("upstream request");
            let mut byte = [0_u8; 1];
            tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
                .await
                .expect("upstream canceled")
                .expect("upstream read")
        });
        let config = pooler_config::compile_yaml(
            "lifecycle.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes: [{{id: pending, listen: local, target: local}}]\n"
            ),
        )
        .expect("lifecycle config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .run_with_drain_timeout(Duration::from_millis(20))
                    .await
            })
        };
        let client = tokio::spawn(async move {
            send_request(address, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").await
        });
        wait_for_active(&server, 1).await;
        server.cancellation_token().cancel();

        let result = tokio::time::timeout(TEST_TIMEOUT, runner)
            .await
            .expect("runner finishes after forced drain")
            .expect("runner task");
        assert!(matches!(result, Err(HttpProxyServerError::Drain(_))));
        assert_eq!(server.active(), 0);
        client.await.expect("client task");
        assert_eq!(upstream.await.expect("upstream task"), 0);
    }

    #[tokio::test]
    async fn patch_route_changes_reasoning_and_preserves_unknown_json() {
        let (upstream_address, upstream) = spawn_one_shot_upstream(b"patched").await;
        let config = pooler_config::compile_yaml(
            "patch.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams: {{local: {{url: http://{upstream_address}}}}}\nroutes:\n  - id: patch\n    listen: local\n    match: {{method: POST, path: /patch}}\n    ingress: {{mode: patch, inspectors: [inspect.openai.model]}}\n    request:\n      steps:\n        - use: transform.json.set_when_model_prefix\n          with: {{prefix: gpt-, pointer: /reasoning/effort, value: high}}\n    target: local\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("patch route compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body =
            br#"{"model":"gpt-5.6-sol","reasoning":{"effort":"low"},"unknown":{"keep":[1,2]}}"#;
        let request = format!(
            "POST /patch HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(status(&response), 200);
        let upstream_request = upstream.await.expect("upstream task");
        let patched: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("patched JSON body");
        assert_eq!(patched["reasoning"]["effort"], "high");
        assert_eq!(patched["unknown"]["keep"], serde_json::json!([1, 2]));
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn request_model_selects_provider_and_rewrites_upstream_model() {
        let fallback_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fallback binds");
        let fallback_address = fallback_listener.local_addr().expect("fallback address");
        let (selected_address, selected_upstream) = spawn_one_shot_upstream(b"selected").await;
        let selected_secret = TestSecret::new("selected-token\n");
        let config = pooler_config::compile_yaml(
            "model-route.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  fallback: {{url: http://{fallback_address}}}\n  selected:\n    url: http://{selected_address}\n    auth: {{secret: {}}}\nmodels:\n  - id: public-model\n    targets:\n      - {{provider: selected, upstream_model: provider-model, capabilities: [text]}}\nroutes:\n  - id: model-route\n    listen: local\n    match: {{method: POST, path: /model}}\n    ingress: {{mode: patch, inspectors: [inspect.openai.model]}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /model, value: mutated-model}}\n    target: {{provider: fallback, model_from: inspected.model}}\n    response: {{mode: opaque}}\n",
                selected_secret.reference()
            ),
        )
        .expect("model route compiles");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let body = br#"{"model":"public-model","unknown":true}"#;
        let request = format!(
            "POST /model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let response = send_request(address, request.as_bytes()).await;
        assert_eq!(response_body(&response), b"selected");
        let upstream_request = selected_upstream.await.expect("selected upstream");
        assert!(String::from_utf8_lossy(&upstream_request)
            .to_ascii_lowercase()
            .contains("authorization: bearer selected-token"));
        let forwarded: serde_json::Value =
            serde_json::from_slice(response_body(&upstream_request)).expect("forwarded JSON");
        assert_eq!(forwarded["model"], "provider-model");
        assert_eq!(forwarded["unknown"], true);
        for invalid_body in [br#"{"model":"unknown"}"#.as_slice(), br#"{}"#.as_slice()] {
            let invalid_request = format!(
                "POST /model HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                invalid_body.len(),
                String::from_utf8_lossy(invalid_body)
            );
            let rejected = send_request(address, invalid_request.as_bytes()).await;
            assert_eq!(status(&rejected), 400);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fallback_listener.accept())
                .await
                .is_err()
        );
        stop_server(&server, runner).await;
    }

    #[tokio::test]
    async fn patch_model_validation_only_runs_for_the_selected_source() {
        let (plain_address, plain_upstream) = spawn_one_shot_upstream(b"plain").await;
        let (selected_address, selected_upstream) = spawn_one_shot_upstream(b"selected").await;
        let config = pooler_config::compile_yaml(
            "model-source.yaml",
            &format!(
                "version: 1\nlisteners: {{local: {{bind: 127.0.0.1:0}}}}\nupstreams:\n  plain: {{url: http://{plain_address}}}\n  selected: {{url: http://{selected_address}}}\nmodels:\n  - id: public\n    targets: [{{provider: selected, upstream_model: private}}]\nroutes:\n  - id: plain\n    listen: local\n    match: {{method: POST, path: /plain}}\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /value, value: true}}\n    target: plain\n    response: {{mode: opaque}}\n  - id: request-model\n    listen: local\n    match: {{method: POST, path: /request-model}}\n    ingress: {{mode: patch}}\n    request:\n      steps:\n        - use: transform.json.set\n          with: {{pointer: /model, value: public}}\n    target: {{provider: plain, model_from: request.model}}\n    response: {{mode: opaque}}\n"
            ),
        )
        .expect("model source config");
        let server = HttpProxyServer::bind(config).await.expect("proxy binds");
        let address = listener_address(&server, "local");
        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };

        for path in ["/plain", "/request-model"] {
            let body = br#"{"model":null,"value":false}"#;
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            );
            let response = send_request(address, request.as_bytes()).await;
            assert_eq!(status(&response), 200);
        }
        let plain_request = plain_upstream.await.expect("plain upstream");
        let plain: serde_json::Value =
            serde_json::from_slice(response_body(&plain_request)).expect("plain patch body");
        assert!(plain["model"].is_null());
        assert_eq!(plain["value"], true);
        let selected_request = selected_upstream.await.expect("selected upstream");
        let selected: serde_json::Value =
            serde_json::from_slice(response_body(&selected_request)).expect("selected patch body");
        assert_eq!(selected["model"], "private");
        stop_server(&server, runner).await;
    }
}
