use std::{net::SocketAddr, time::Duration};

use futures_util::{SinkExt, StreamExt};
use pooler_config::compile_yaml;
use pooler_server::HttpProxyServer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::{
    accept_async,
    tungstenite::{handshake::derive_accept_key, Message},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

#[tokio::test]
async fn websocket_proxy_reassembles_fragments_and_forwards_ping() {
    let (upstream_address, upstream_task) = spawn_echo_upstream().await;
    let (server, address, runner) = start_server(upstream_address, 64).await;
    let mut client = raw_handshake(address).await;

    client
        .write_all(&client_frame(false, 0x1, b"frag"))
        .await
        .expect("first fragmented frame");
    client
        .write_all(&client_frame(true, 0x0, b"mented"))
        .await
        .expect("continuation frame");
    let (_, opcode, payload) = read_frame(&mut client).await;
    assert_eq!(opcode, 0x1);
    assert_eq!(payload, b"fragmented");

    client
        .write_all(&client_frame(true, 0x9, b"ping"))
        .await
        .expect("ping frame");
    let (_, opcode, payload) = read_frame(&mut client).await;
    assert_eq!(opcode, 0xA);
    assert_eq!(payload, b"ping");

    client
        .write_all(&client_frame(true, 0x8, &[]))
        .await
        .expect("close frame");
    let _ = timeout(TEST_TIMEOUT, client.shutdown()).await;
    shutdown(server, runner).await;
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn websocket_proxy_cancels_upstream_when_downstream_disconnects() {
    let (upstream_address, upstream_task) = spawn_echo_upstream().await;
    let (server, address, runner) = start_server(upstream_address, 64).await;
    let client = raw_handshake(address).await;
    drop(client);

    timeout(TEST_TIMEOUT, upstream_task)
        .await
        .expect("upstream observes downstream cancellation")
        .expect("upstream task");
    shutdown(server, runner).await;
}

#[tokio::test]
async fn websocket_proxy_rejects_an_oversize_message_with_1009() {
    let (upstream_address, upstream_task) = spawn_echo_upstream().await;
    let (server, address, runner) = start_server(upstream_address, 8).await;
    let mut client = raw_handshake(address).await;
    client
        .write_all(&client_frame(true, 0x1, b"message-too-large"))
        .await
        .expect("oversize frame");

    let (_, opcode, payload) = read_frame(&mut client).await;
    assert_eq!(opcode, 0x8);
    assert!(payload.len() >= 2);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1009);

    drop(client);
    shutdown(server, runner).await;
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn websocket_proxy_rejects_invalid_fragmented_utf8_with_1007() {
    let (upstream_address, upstream_task) = spawn_echo_upstream().await;
    let (server, address, runner) = start_server(upstream_address, 64).await;
    let mut client = raw_handshake(address).await;
    client
        .write_all(&client_frame(false, 0x1, &[0xC3]))
        .await
        .expect("invalid text prefix");
    client
        .write_all(&client_frame(true, 0x0, &[0x28]))
        .await
        .expect("invalid text continuation");

    let (_, opcode, payload) = read_frame(&mut client).await;
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1007);

    drop(client);
    shutdown(server, runner).await;
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn websocket_proxy_rejects_reserved_close_code_with_1002() {
    let (upstream_address, upstream_task) = spawn_echo_upstream().await;
    let (server, address, runner) = start_server(upstream_address, 64).await;
    let mut client = raw_handshake(address).await;
    client
        .write_all(&client_frame(true, 0x8, &[0x03, 0xED]))
        .await
        .expect("reserved close code");

    let (_, opcode, payload) = read_frame(&mut client).await;
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1002);

    drop(client);
    shutdown(server, runner).await;
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn websocket_proxy_rejects_upstream_without_upgrade_headers() {
    let (upstream_address, upstream_task) = spawn_invalid_handshake().await;
    let (server, address, runner) = start_server(upstream_address, 64).await;
    let (mut client, response) = raw_handshake_response(address, "").await;
    assert!(
        response.starts_with(b"HTTP/1.1 502"),
        "response: {response:?}"
    );
    client.shutdown().await.expect("close downstream");

    shutdown(server, runner).await;
    upstream_task.await.expect("upstream task");
}

#[tokio::test]
async fn websocket_proxy_rejects_unrequested_upstream_subprotocol() {
    let (upstream_address, upstream_task) = spawn_subprotocol_handshake().await;
    let (server, address, runner) = start_server(upstream_address, 64).await;
    let (mut client, response) =
        raw_handshake_response(address, "Sec-WebSocket-Protocol: client-only\r\n").await;
    assert!(
        response.starts_with(b"HTTP/1.1 502"),
        "response: {response:?}"
    );
    client.shutdown().await.expect("close downstream");

    shutdown(server, runner).await;
    upstream_task.await.expect("upstream task");
}

async fn start_server(
    upstream_address: SocketAddr,
    max_frame_bytes: u64,
) -> (
    HttpProxyServer,
    SocketAddr,
    JoinHandle<Result<(), pooler_server::HttpProxyServerError>>,
) {
    let config_text = format!(
        "version: 2\nlisteners:\n  local:\n    bind: 127.0.0.1:0\nupstreams:\n  socket:\n    url: ws://{upstream_address}/fixed-origin\nroutes:\n  - id: socket\n    listen: local\n    match:\n      method: GET\n      path: /socket\n      websocket: true\n    limits:\n      max_frame_bytes: {max_frame_bytes}\n      request_timeout: 10s\n    target:\n      provider: socket\n      upstream_path: /echo\n"
    );
    let config =
        compile_yaml("websocket-test.yaml", &config_text).expect("WebSocket config compiles");
    let server = HttpProxyServer::bind(config)
        .await
        .expect("WebSocket server binds");
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
        .expect("server task joins")
        .expect("server run succeeds");
}

async fn spawn_echo_upstream() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("upstream accepts");
        let mut socket = accept_async(stream).await.expect("upstream handshake");
        while let Some(message) = socket.next().await {
            match message.expect("upstream message") {
                Message::Text(text) => socket.send(Message::Text(text)).await.expect("echo text"),
                Message::Binary(bytes) => socket
                    .send(Message::Binary(bytes))
                    .await
                    .expect("echo binary"),
                Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.expect("echo pong"),
                Message::Close(frame) => {
                    let _ = socket.send(Message::Close(frame)).await;
                    break;
                }
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    });
    (address, task)
}

async fn spawn_invalid_handshake() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let _ = read_headers(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: invalid\r\n\r\n")
            .await
            .expect("invalid handshake response");
    });
    (address, task)
}

async fn spawn_subprotocol_handshake() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("upstream accepts");
        let request = read_headers(&mut stream).await;
        let key = header_value(&request, "sec-websocket-key").expect("upstream key");
        let accept = derive_accept_key(key.as_bytes());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: server-only\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("subprotocol response");
    });
    (address, task)
}

async fn raw_handshake(address: SocketAddr) -> TcpStream {
    let (stream, response) = raw_handshake_response(address, "").await;
    assert!(
        response.starts_with(b"HTTP/1.1 101"),
        "response: {response:?}"
    );
    stream
}

async fn raw_handshake_response(address: SocketAddr, extra_headers: &str) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("downstream connects");
    let request = format!(
        "GET /socket HTTP/1.1\r\nHost: client.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n{extra_headers}\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write WebSocket handshake");
    let response = read_headers(&mut stream).await;
    (stream, response)
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let read = timeout(TEST_TIMEOUT, stream.read(&mut chunk))
            .await
            .expect("read headers")
            .expect("header read");
        assert!(read > 0, "connection closed before headers");
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            return bytes;
        }
    }
}

fn header_value<'a>(headers: &'a [u8], wanted: &str) -> Option<&'a str> {
    std::str::from_utf8(headers)
        .ok()?
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.trim())
}

fn client_frame(final_frame: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(if final_frame { 0x80 | opcode } else { opcode });
    let mask = [1_u8, 2, 3, 4];
    match payload.len() {
        0..=125 => frame.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    frame
}

async fn read_frame(stream: &mut TcpStream) -> (bool, u8, Vec<u8>) {
    let mut header = [0_u8; 2];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut header))
        .await
        .expect("frame header")
        .expect("frame header read");
    let final_frame = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0F;
    let mut length = u64::from(header[1] & 0x7F);
    if length == 126 {
        let mut extended = [0_u8; 2];
        stream
            .read_exact(&mut extended)
            .await
            .expect("extended length");
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        stream
            .read_exact(&mut extended)
            .await
            .expect("extended length");
        length = u64::from_be_bytes(extended);
    }
    let mut payload = vec![0_u8; usize::try_from(length).expect("test frame length")];
    stream
        .read_exact(&mut payload)
        .await
        .expect("frame payload");
    (final_frame, opcode, payload)
}
