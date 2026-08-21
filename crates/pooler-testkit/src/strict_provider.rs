//! Strict provider fakes for mounted end-to-end tests.
//!
//! A permissive fake that answers `200 OK` to anything proves only that bytes
//! left the process. These fakes encode what a real provider endpoint accepts —
//! path, method, credential placement, required headers, content type, query
//! shape, and body shape — and reject anything else with the status the real
//! endpoint would use, recording why.
//!
//! A test therefore fails when Pooler sends a request the provider would have
//! refused, instead of passing because the fake was generous.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// One endpoint a provider serves.
#[derive(Clone, Copy, Debug)]
pub struct ProviderRoute {
    /// Accepted method.
    pub method: &'static str,
    /// Accepted path. One `*` matches a non-empty run of path bytes.
    pub path: &'static str,
    /// Required request content type, if the endpoint takes a body.
    pub content_type: Option<&'static str>,
    /// Top-level JSON fields the endpoint requires in a request body.
    pub required_body_fields: &'static [&'static str],
    /// Body returned when the request is accepted.
    pub response: &'static str,
}

/// What one provider accepts on the wire.
#[derive(Clone, Copy, Debug)]
pub struct ProviderContract {
    /// Provider name, used in rejection messages.
    pub name: &'static str,
    /// Header carrying the credential.
    pub credential_header: &'static str,
    /// Non-secret prefix before the credential value.
    pub credential_prefix: &'static str,
    /// Non-secret headers the provider requires on every request.
    pub required_headers: &'static [(&'static str, &'static str)],
    /// Endpoints this provider serves.
    pub routes: &'static [ProviderRoute],
}

/// Credential headers a provider must never receive from another provider, or
/// from the downstream caller.
const FOREIGN_CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "x-api-key", "x-goog-api-key"];

const OPENAI_MODELS: &str = r#"{"data":[{"id":"gpt-4o"}]}"#;
const ANTHROPIC_MODELS: &str = r#"{"data":[{"id":"claude-sonnet-4"}]}"#;
const GEMINI_MODELS: &str = r#"{"models":[{"name":"models/gemini-2.5-pro","supportedGenerationMethods":["generateContent","streamGenerateContent","countTokens"]}]}"#;
const ACCEPTED: &str = r#"{"ok":true}"#;

impl ProviderContract {
    /// OpenAI: bearer credential, JSON bodies carrying a model.
    #[must_use]
    pub const fn openai() -> Self {
        Self {
            name: "openai",
            credential_header: "authorization",
            credential_prefix: "Bearer ",
            required_headers: &[],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/v1/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: OPENAI_MODELS,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/chat/completions",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "messages"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/responses",
                    content_type: Some("application/json"),
                    required_body_fields: &["model"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/responses/compact",
                    content_type: Some("application/json"),
                    required_body_fields: &["model"],
                    response: ACCEPTED,
                },
            ],
        }
    }

    /// Anthropic: `x-api-key` credential and a required version header.
    #[must_use]
    pub const fn anthropic() -> Self {
        Self {
            name: "anthropic",
            credential_header: "x-api-key",
            credential_prefix: "",
            required_headers: &[("anthropic-version", "2023-06-01")],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/v1/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: ANTHROPIC_MODELS,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/messages",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "messages"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/messages/count_tokens",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "messages"],
                    response: ACCEPTED,
                },
            ],
        }
    }

    /// Gemini: `x-goog-api-key` credential and model actions in the path.
    #[must_use]
    pub const fn gemini() -> Self {
        Self {
            name: "gemini",
            credential_header: "x-goog-api-key",
            credential_prefix: "",
            required_headers: &[],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/v1beta/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: GEMINI_MODELS,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1beta/models/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1beta/models/*:generateContent",
                    content_type: Some("application/json"),
                    required_body_fields: &["contents"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1beta/models/*:streamGenerateContent",
                    content_type: Some("application/json"),
                    required_body_fields: &["contents"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1beta/models/*:countTokens",
                    content_type: Some("application/json"),
                    required_body_fields: &["contents"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1beta/interactions",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "input"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1beta/interactions/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "DELETE",
                    path: "/v1beta/interactions/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1beta/interactions/*/cancel",
                    content_type: Some("application/json"),
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
            ],
        }
    }
}

/// One request the provider accepted.
#[derive(Clone, Debug)]
pub struct AcceptedRequest {
    /// Request method.
    pub method: String,
    /// Request path without the query string.
    pub path: String,
    /// Query string, if any.
    pub query: Option<String>,
    /// Lowercased request headers.
    pub headers: BTreeMap<String, String>,
    /// Request body.
    pub body: String,
}

impl AcceptedRequest {
    /// Return one header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// Everything one strict provider observed.
#[derive(Clone, Debug, Default)]
pub struct ProviderLog {
    /// Requests the provider accepted, in order.
    pub accepted: Vec<AcceptedRequest>,
    /// Reasons the provider refused a request, in order.
    pub rejected: Vec<String>,
}

impl ProviderLog {
    /// Requests accepted for one path.
    #[must_use]
    pub fn accepted_for(&self, path: &str) -> Option<&AcceptedRequest> {
        self.accepted.iter().find(|request| request.path == path)
    }

    /// Panic when the provider refused anything, naming every reason.
    ///
    /// This is the assertion that turns a generous fake into a contract: a
    /// request the real provider would have refused fails the test here.
    pub fn assert_accepted_everything(&self) {
        assert!(
            self.rejected.is_empty(),
            "the {} provider refused {} request(s): {:?}",
            self.accepted.len() + self.rejected.len(),
            self.rejected.len(),
            self.rejected
        );
    }
}

/// A provider fake bound to a loopback port.
///
/// The listener is owned for the whole lifetime of the proxy under test and is
/// stopped only after that proxy has drained, so the log is exact rather than
/// dependent on machine load.
pub struct StrictProvider {
    address: SocketAddr,
    shutdown: Arc<Notify>,
    task: JoinHandle<ProviderLog>,
}

impl StrictProvider {
    /// Bind a provider fake enforcing `contract` with `credential`.
    ///
    /// # Panics
    ///
    /// Panics when the loopback listener cannot be bound.
    pub async fn start(contract: ProviderContract, credential: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("strict provider binds");
        let address = listener.local_addr().expect("strict provider address");
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(serve(
            listener,
            contract,
            credential.to_owned(),
            Arc::clone(&shutdown),
        ));
        Self {
            address,
            shutdown,
            task,
        }
    }

    /// Address this provider listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting and return the log.
    ///
    /// Call this only once the proxy under test has drained.
    ///
    /// # Panics
    ///
    /// Panics when the serving task panicked.
    pub async fn finish(self) -> ProviderLog {
        self.shutdown.notify_one();
        self.task.await.expect("strict provider task")
    }
}

async fn serve(
    listener: TcpListener,
    contract: ProviderContract,
    credential: String,
    shutdown: Arc<Notify>,
) -> ProviderLog {
    let mut log = ProviderLog::default();
    loop {
        let accepted = tokio::select! {
            biased;
            accepted = listener.accept() => accepted,
            () = shutdown.notified() => break,
        };
        let Ok((mut stream, _)) = accepted else {
            break;
        };
        let Some(request) = read_request(&mut stream).await else {
            log.rejected
                .push(format!("{}: truncated request", contract.name));
            continue;
        };
        match check(&contract, &credential, &request) {
            Ok(body) => {
                respond(&mut stream, 200, "OK", body).await;
                log.accepted.push(request);
            }
            Err(rejection) => {
                respond(&mut stream, rejection.status, rejection.reason_phrase, "{}").await;
                log.rejected.push(format!(
                    "{} {} {} -> {} {}",
                    contract.name, request.method, request.path, rejection.status, rejection.detail
                ));
            }
        }
    }
    log
}

struct Rejection {
    status: u16,
    reason_phrase: &'static str,
    detail: String,
}

impl Rejection {
    fn new(status: u16, reason_phrase: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            reason_phrase,
            detail: detail.into(),
        }
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == path;
    };
    if !path.starts_with(prefix)
        || !path.ends_with(suffix)
        || path.len() <= prefix.len().saturating_add(suffix.len())
    {
        return false;
    }
    let wildcard = &path[prefix.len()..path.len() - suffix.len()];
    !wildcard.contains('/')
}

fn check(
    contract: &ProviderContract,
    credential: &str,
    request: &AcceptedRequest,
) -> Result<&'static str, Rejection> {
    // The credential must be present, correct, and in this provider's header.
    let expected = format!("{}{credential}", contract.credential_prefix);
    match request.header(contract.credential_header) {
        Some(value) if value == expected => {}
        Some(_) => {
            return Err(Rejection::new(
                401,
                "Unauthorized",
                format!("{} holds the wrong value", contract.credential_header),
            ));
        }
        None => {
            return Err(Rejection::new(
                401,
                "Unauthorized",
                format!("{} is missing", contract.credential_header),
            ));
        }
    }
    // No other provider's credential header may be present, so a smuggled or
    // misplaced credential fails here rather than being silently accepted.
    for header in FOREIGN_CREDENTIAL_HEADERS {
        if header.eq_ignore_ascii_case(contract.credential_header) {
            continue;
        }
        if request.header(header).is_some() {
            return Err(Rejection::new(
                401,
                "Unauthorized",
                format!("unexpected credential header {header}"),
            ));
        }
    }
    for (name, value) in contract.required_headers {
        if request.header(name) != Some(*value) {
            return Err(Rejection::new(
                400,
                "Bad Request",
                format!("{name} must be {value}"),
            ));
        }
    }
    let matching: Vec<&ProviderRoute> = contract
        .routes
        .iter()
        .filter(|route| path_matches(route.path, &request.path))
        .collect();
    if matching.is_empty() {
        return Err(Rejection::new(404, "Not Found", "no such endpoint"));
    }
    let Some(route) = matching.iter().find(|route| route.method == request.method) else {
        return Err(Rejection::new(
            405,
            "Method Not Allowed",
            format!("{} is not allowed here", request.method),
        ));
    };
    if let Some(query) = &request.query {
        let documented_stream_query =
            route.path.ends_with(":streamGenerateContent") && query == "alt=sse";
        if !documented_stream_query {
            return Err(Rejection::new(
                400,
                "Bad Request",
                format!("unexpected query string {query}"),
            ));
        }
    }

    match (route.content_type, request.header("content-type")) {
        (Some(expected), Some(actual)) if actual.starts_with(expected) => {}
        (Some(expected), actual) => {
            return Err(Rejection::new(
                415,
                "Unsupported Media Type",
                format!("content-type must be {expected}, got {actual:?}"),
            ));
        }
        (None, _) => {}
    }

    if !route.required_body_fields.is_empty() {
        let Ok(body) = serde_json::from_str::<serde_json::Value>(&request.body) else {
            return Err(Rejection::new(400, "Bad Request", "body is not JSON"));
        };
        for field in route.required_body_fields {
            if body.get(field).is_none() {
                return Err(Rejection::new(
                    422,
                    "Unprocessable Entity",
                    format!("body is missing `{field}`"),
                ));
            }
        }
    }
    Ok(route.response)
}

async fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
}

async fn read_request(stream: &mut TcpStream) -> Option<AcceptedRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let head = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let mut lines = head.lines();
        let mut start = lines.next()?.split(' ');
        let method = start.next()?.to_owned();
        let target = start.next()?;
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| {
                (path, Some(query.to_owned()))
            });
        let headers: BTreeMap<String, String> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        return Some(AcceptedRequest {
            method,
            path: path.to_owned(),
            query,
            headers,
            body: String::from_utf8_lossy(&bytes[header_end..]).to_string(),
        });
    }
}
