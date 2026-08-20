use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use pooler_config::compile_yaml;
use pooler_server::{HttpProxyServer, HttpProxyServerError};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

const CERTIFICATE: &[u8] = include_bytes!("fixtures/localhost-cert.pem");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/localhost-key.pem");
const MISMATCH_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/mismatch-key.pem");
const ROTATED_CERTIFICATE: &[u8] = include_bytes!("fixtures/rotated-cert.pem");
const ROTATED_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/rotated-key.pem");
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn tls_listener_serves_https_with_sni_and_alpn() {
    let files = FixtureFiles::new();
    let (upstream, upstream_task) = one_shot_upstream(b"hello over tls").await;
    let config = compile_yaml(
        "tls-test.yaml",
        &config_text(&files, upstream, "http/1.1", "10s"),
    )
    .expect("TLS config compiles");
    let server = HttpProxyServer::bind(config).await.expect("TLS binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("listener address")
        .address()
        .parse::<SocketAddr>()
        .expect("TCP listener address");
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let mut client = connect_tls(address).await;
    assert_eq!(
        client.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write HTTPS request");
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .expect("HTTPS response completes")
        .expect("read HTTPS response");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "response: {response:?}"
    );
    assert!(
        response.ends_with(b"hello over tls"),
        "response: {response:?}"
    );
    upstream_task.await.expect("upstream task");

    server.begin_drain();
    timeout(TEST_TIMEOUT, runner)
        .await
        .expect("server drains")
        .expect("server task joins")
        .expect("server run succeeds");
}

#[tokio::test]
async fn tls_listener_rejects_group_readable_private_key() {
    let files = FixtureFiles::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&files.key, fs::Permissions::from_mode(0o644))
            .expect("make key insecure");
    }
    let config = compile_yaml(
        "tls-insecure-key.yaml",
        &config_text(
            &files,
            "127.0.0.1:1".parse().expect("address"),
            "http/1.1",
            "10s",
        ),
    )
    .expect("TLS config compiles before file checks");
    let error = HttpProxyServer::bind(config)
        .await
        .expect_err("insecure key is rejected");
    let message = error.to_string();
    assert!(message.contains("owner-private"), "error: {message}");
    assert!(
        !message.contains("BEGIN PRIVATE KEY"),
        "secret leaked: {message}"
    );
}

#[tokio::test]
async fn tls_listener_negotiates_h2_only_when_auto_protocol_is_enabled() {
    let files = FixtureFiles::new();
    let config_text = config_text(&files, "127.0.0.1:1".parse().expect("address"), "h2", "10s")
        .replace("    tls:\n", "    protocol: auto\n    tls:\n");
    let config = compile_yaml("tls-h2.yaml", &config_text).expect("TLS h2 config compiles");
    let server = HttpProxyServer::bind(config).await.expect("TLS binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("listener address")
        .address()
        .parse::<SocketAddr>()
        .expect("TCP listener address");
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };
    let client = connect_tls_with_alpn(address, b"h2").await;
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    server.begin_drain();
    timeout(TEST_TIMEOUT, runner)
        .await
        .expect("server drains")
        .expect("server task joins")
        .expect("server run succeeds");
}

#[tokio::test]
async fn tls_listener_rejects_certificate_key_mismatch() {
    let files = FixtureFiles::new();
    let mismatch_key = files.directory.path().join("mismatch-key.pem");
    fs::write(&mismatch_key, MISMATCH_PRIVATE_KEY).expect("mismatch key fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&mismatch_key, fs::Permissions::from_mode(0o600))
            .expect("mismatch key permissions");
    }
    let config = compile_yaml(
        "tls-mismatch.yaml",
        &config_text_with_key(
            &files,
            "127.0.0.1:1".parse().expect("address"),
            "http/1.1",
            "10s",
            "mismatch-key.pem",
        ),
    )
    .expect("TLS config compiles before identity checks");
    let error = HttpProxyServer::bind(config)
        .await
        .expect_err("mismatched key is rejected");
    assert!(error.to_string().contains("certificate and private key"));
}

#[tokio::test]
async fn tls_listener_cancels_a_pending_handshake_during_drain() {
    let files = FixtureFiles::new();
    let config = compile_yaml(
        "tls-cancel.yaml",
        &config_text(
            &files,
            "127.0.0.1:1".parse().expect("address"),
            "http/1.1",
            "30s",
        ),
    )
    .expect("TLS config compiles");
    let server = HttpProxyServer::bind(config).await.expect("TLS binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("listener address")
        .address()
        .parse::<SocketAddr>()
        .expect("TCP listener address");
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };
    let _raw = TcpStream::connect(address).await.expect("raw TCP connects");
    server.begin_drain();
    timeout(TEST_TIMEOUT, runner)
        .await
        .expect("pending handshake drains")
        .expect("server task joins")
        .expect("server run succeeds");
}

#[tokio::test]
async fn tls_reload_rotates_same_path_for_new_connections_and_keeps_old_tls_alive() {
    let files = FixtureFiles::new();
    let config = compile_yaml(
        "tls-rotation.yaml",
        &config_text(
            &files,
            "127.0.0.1:1".parse().expect("address"),
            "http/1.1",
            "10s",
        ),
    )
    .expect("TLS config compiles");
    let server = HttpProxyServer::bind(config).await.expect("TLS binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("listener address")
        .address()
        .parse::<SocketAddr>()
        .expect("TCP listener address");
    let runner = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };

    let old_client = connect_tls(address).await;
    let old_certificate = peer_certificate(&old_client);
    assert_eq!(old_certificate, first_certificate(CERTIFICATE));

    files.rotate();
    let candidate = compile_yaml(
        "tls-rotation.yaml",
        &config_text(
            &files,
            "127.0.0.1:1".parse().expect("address"),
            "http/1.1",
            "10s",
        ),
    )
    .expect("rotated TLS config compiles");
    let outcome = server
        .reload(candidate)
        .await
        .expect("TLS rotation reloads");
    assert!(outcome.changed(), "file contents changed at the same paths");

    let new_client = connect_tls(address).await;
    assert_eq!(
        peer_certificate(&new_client),
        first_certificate(ROTATED_CERTIFICATE)
    );
    assert_eq!(peer_certificate(&old_client), old_certificate);

    server.begin_drain();
    timeout(TEST_TIMEOUT, runner)
        .await
        .expect("server drains")
        .expect("server task joins")
        .expect("server run succeeds");
}

#[tokio::test]
async fn tls_reload_rejects_bound_path_changes_without_rebinding() {
    let files = FixtureFiles::new();
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let config = compile_yaml(
        "tls-reload.yaml",
        &config_text(&files, upstream_address, "http/1.1", "10s"),
    )
    .expect("TLS config compiles");
    let server = HttpProxyServer::bind(config).await.expect("TLS binds");
    let address = server
        .listener_addresses()
        .first()
        .expect("listener address")
        .address()
        .to_owned();

    let changed = compile_yaml(
        "tls-reload.yaml",
        &config_text(&files, upstream_address, "http/1.1", "10s")
            .replace("bind: 127.0.0.1:0", "bind: 127.0.0.1:1"),
    )
    .expect("changed TLS config compiles");
    let error = server
        .reload(changed)
        .await
        .expect_err("identity reload rejected");
    assert!(matches!(error, HttpProxyServerError::ListenerSetChanged));
    assert_eq!(server.listener_addresses()[0].address(), address);
}

async fn connect_tls(address: SocketAddr) -> TlsStream<TcpStream> {
    connect_tls_with_alpn(address, b"http/1.1").await
}

async fn connect_tls_with_alpn(address: SocketAddr, alpn: &[u8]) -> TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    add_root(&mut roots, CERTIFICATE);
    add_root(&mut roots, ROTATED_CERTIFICATE);
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await.expect("TLS TCP connects");
    connector
        .connect(
            ServerName::try_from("localhost")
                .expect("server name")
                .to_owned(),
            stream,
        )
        .await
        .expect("TLS handshake")
}

fn add_root(roots: &mut RootCertStore, pem: &[u8]) {
    let certificate = CertificateDer::pem_slice_iter(pem)
        .next()
        .expect("certificate entry")
        .expect("certificate parses");
    roots.add(certificate).expect("certificate root");
}

fn first_certificate(pem: &[u8]) -> Vec<u8> {
    let certificate = CertificateDer::pem_slice_iter(pem)
        .next()
        .expect("certificate entry")
        .expect("certificate parses");
    certificate.as_ref().to_vec()
}

fn peer_certificate(stream: &TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .expect("server certificate")
        .first()
        .expect("end-entity certificate")
        .as_ref()
        .to_vec()
}

async fn one_shot_upstream(body: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.expect("upstream reads");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("upstream headers");
        stream.write_all(body).await.expect("upstream body");
    });
    (address, task)
}

fn config_text(files: &FixtureFiles, upstream: SocketAddr, alpn: &str, handshake: &str) -> String {
    config_text_with_key(files, upstream, alpn, handshake, "key.pem")
}

fn config_text_with_key(
    files: &FixtureFiles,
    upstream: SocketAddr,
    alpn: &str,
    handshake: &str,
    key_name: &str,
) -> String {
    let key = if key_name == "key.pem" {
        files.key.display().to_string()
    } else {
        files.directory.path().join(key_name).display().to_string()
    };
    format!(
        "version: 1\nlisteners:\n  local:\n    bind: 127.0.0.1:0\n    tls:\n      cert: {:?}\n      key: {:?}\n      alpn: [{alpn}]\n      handshake_timeout: {handshake}\nupstreams:\n  local:\n    url: http://{upstream}\nroutes:\n  - id: route\n    listen: local\n    match: {{path: /}}\n    target: local\n",
        files.cert.display(), key
    )
}

struct FixtureFiles {
    directory: TempDir,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl FixtureFiles {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        fs::write(&cert, CERTIFICATE).expect("certificate fixture");
        fs::write(&key, PRIVATE_KEY).expect("key fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cert, fs::Permissions::from_mode(0o600))
                .expect("certificate permissions");
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key permissions");
        }
        Self {
            directory,
            cert,
            key,
        }
    }

    fn rotate(&self) {
        fs::write(&self.cert, ROTATED_CERTIFICATE).expect("rotated certificate");
        fs::write(&self.key, ROTATED_PRIVATE_KEY).expect("rotated private key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.cert, fs::Permissions::from_mode(0o600))
                .expect("rotated certificate permissions");
            fs::set_permissions(&self.key, fs::Permissions::from_mode(0o600))
                .expect("rotated key permissions");
        }
    }
}
