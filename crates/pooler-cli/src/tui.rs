//! Thin terminal dashboard backed only by the authenticated management API.

use std::io::{self, Write as _};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use pooler_auth::{HyperOAuthTransport, OAuthHttpRequest, OAuthTransport, SecretRef, SecretValue};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_MANAGEMENT_RESPONSE_BYTES: usize = 256 * 1024;
const VIEWS: [(&str, &str); 5] = [
    ("Health", "health"),
    ("Active generation", "active"),
    ("Provider health", "health/providers"),
    ("Accounts", "accounts"),
    ("Quota", "quota"),
];

pub(crate) fn run(endpoint: &str, token_ref: &str, once: bool, interval_secs: u64) -> Result<()> {
    if !(1..=300).contains(&interval_secs) {
        return Err(anyhow!(
            "TUI refresh interval must be between 1 and 300 seconds"
        ));
    }
    let base = validate_endpoint(endpoint)?;
    let token = SecretRef::parse(token_ref)
        .context("invalid TUI management token reference")?
        .resolve()
        .context("could not resolve TUI management token")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize TUI runtime")?;
    runtime.block_on(async move {
        let transport = HyperOAuthTransport::new(MAX_MANAGEMENT_RESPONSE_BYTES)
            .context("could not initialize management API transport")?;
        loop {
            let snapshot = fetch_snapshot(&transport, &base, &token).await;
            render(&base, &snapshot)?;
            if once {
                return snapshot
                    .into_iter()
                    .find_map(|(_, result)| result.err())
                    .map_or(Ok(()), Err);
            }
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    })
}

async fn fetch_snapshot(
    transport: &HyperOAuthTransport,
    base: &Url,
    token: &SecretValue,
) -> Vec<(&'static str, Result<Value>)> {
    let mut snapshot = Vec::with_capacity(VIEWS.len());
    for (label, path) in VIEWS {
        let result = fetch_view(transport, base, path, token.clone()).await;
        snapshot.push((label, result));
    }
    snapshot
}

async fn fetch_view(
    transport: &HyperOAuthTransport,
    base: &Url,
    path: &str,
    token: SecretValue,
) -> Result<Value> {
    let url = base
        .join(path)
        .map_err(|_| anyhow!("management API path could not be constructed"))?;
    let request = OAuthHttpRequest::get(url).with_bearer_auth(token);
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        transport.send(request, CancellationToken::new()),
    )
    .await
    .map_err(|_| anyhow!("management API request timed out"))?
    .map_err(|_| anyhow!("management API request failed"))?;
    if !(200..300).contains(&response.status()) {
        return Err(anyhow!(
            "management API returned HTTP {}",
            response.status()
        ));
    }
    serde_json::from_slice(response.body_bytes())
        .map_err(|_| anyhow!("management API returned invalid JSON"))
}

fn validate_endpoint(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("invalid TUI management endpoint")?;
    let loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if (url.scheme() != "https" && !loopback_http)
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(anyhow!(
            "TUI endpoint must be HTTPS or loopback HTTP and contain no credentials or query"
        ));
    }
    url.set_path("/management/");
    Ok(url)
}

fn render(base: &Url, snapshot: &[(&str, Result<Value>)]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    write!(stdout, "\x1b[2J\x1b[H")?;
    writeln!(
        stdout,
        "Pooler management — {}",
        base.origin().ascii_serialization()
    )?;
    writeln!(stdout, "API-backed live view; Ctrl-C exits.\n")?;
    for (label, result) in snapshot {
        writeln!(stdout, "== {label} ==")?;
        match result {
            Ok(value) => writeln!(stdout, "{}", serde_json::to_string_pretty(value)?)?,
            Err(error) => writeln!(stdout, "unavailable: {error}")?,
        }
        writeln!(stdout)?;
    }
    stdout.flush().context("flush TUI output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_rejects_remote_cleartext_and_embedded_credentials() {
        for value in [
            "http://example.com:18477",
            "https://token@example.com",
            "https://example.com?token=secret",
        ] {
            assert!(validate_endpoint(value).is_err(), "accepted {value}");
        }
        assert_eq!(
            validate_endpoint("http://127.0.0.1:18477")
                .expect("loopback")
                .as_str(),
            "http://127.0.0.1:18477/management/"
        );
    }

    #[tokio::test]
    async fn view_is_fetched_only_through_authenticated_management_http() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let count = stream.read(&mut request).await.expect("request");
            let request = std::str::from_utf8(&request[..count]).expect("UTF-8 request");
            assert!(request.starts_with("GET /management/health HTTP/1.1\r\n"));
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer test-token\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"ok\":true}",
                )
                .await
                .expect("response");
        });
        let transport = HyperOAuthTransport::new(1024).expect("transport");
        let base = Url::parse(&format!("http://{address}/management/")).expect("base URL");
        let value = fetch_view(&transport, &base, "health", SecretValue::new("test-token"))
            .await
            .expect("management view");
        assert_eq!(value["ok"], true);
        server.await.expect("server");
    }
}
