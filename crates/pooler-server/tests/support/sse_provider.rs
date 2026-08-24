//! Small strict HTTP/SSE fixture used by native provider wire tests.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct SseProvider {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    task: JoinHandle<()>,
}

impl SseProvider {
    pub async fn start(response_body: &'static [u8], content_type: &'static str) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("strict SSE listener");
        let address = listener.local_addr().expect("strict SSE address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut bytes = Vec::new();
            let mut one = [0_u8; 1];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                if stream.read_exact(&mut one).await.is_err() {
                    return;
                }
                bytes.push(one[0]);
                if bytes.len() > 64 * 1024 {
                    return;
                }
            }
            let content_length = bytes
                .split(|byte| *byte == b'\n')
                .find_map(|line| {
                    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let mut body = vec![0_u8; content_length];
            if stream.read_exact(&mut body).await.is_err() {
                return;
            }
            let (head, body) = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map_or((&bytes[..], body.as_slice()), |separator| {
                    (&bytes[..separator], body.as_slice())
                });
            let mut lines = head.split(|byte| *byte == b'\n');
            let request_line = lines
                .next()
                .and_then(|line| std::str::from_utf8(line).ok())
                .unwrap_or_default()
                .trim_end_matches('\r');
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_owned();
            let target = request_parts.next().unwrap_or_default().to_owned();
            let headers = lines
                .filter_map(|line| {
                    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
                    let (name, value) = line.split_once(':')?;
                    Some((name.to_ascii_lowercase(), value.trim().to_owned()))
                })
                .collect::<Vec<_>>();
            captured
                .lock()
                .expect("strict SSE request lock")
                .push(RecordedRequest {
                    method,
                    target,
                    headers,
                    body: body.to_vec(),
                });
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response_body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(response_body).await;
            let _ = stream.shutdown().await;
        });
        Self {
            address,
            requests,
            task,
        }
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub async fn finish(self) -> Vec<RecordedRequest> {
        let Self { requests, task, .. } = self;
        let _ = task.await;
        let captured = requests.lock().expect("strict SSE request lock").clone();
        captured
    }
}
