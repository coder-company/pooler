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

const OPENAI_MODELS: &str = r#"{"data":[{"id":"gpt-4o"},{"id":"text-embedding-3-small"}]}"#;
const KIMI_MODELS: &str = r#"{"data":[{"id":"kimi-k2.5","object":"model"}]}"#;
const VERTEX_MODELS: &str = r#"{"publisherModels":[{"name":"publishers/google/models/gemini-2.5-pro","supportedActions":["generateContent","streamGenerateContent","countTokens"]}]}"#;
const VERTEX_GENERATE_RESPONSE: &str = r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"sanitized"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2},"modelVersion":"gemini-2.5-pro"}"#;
const VERTEX_STREAM_RESPONSE: &str = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"sanitized\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2},\"modelVersion\":\"gemini-2.5-pro\"}\n\n";
const ANTIGRAVITY_MODELS: &str = r#"{"webSearchModelIds":["GEMINI-FIXTURE","claude-fixture"]}"#;
const COMPATIBLE_MODELS: &str = r#"{"object":"list","data":[{"id":"vendor-model","object":"model","owned_by":"fixture-vendor"}]}"#;
const XAI_MODELS: &str = r#"{"data":[{"id":"grok-4.1-fast"}]}"#;
const ANTHROPIC_MODELS: &str = r#"{"data":[{"id":"claude-sonnet-4"}]}"#;
const GEMINI_MODELS: &str = r#"{"models":[{"name":"models/gemini-2.5-pro","supportedGenerationMethods":["generateContent","streamGenerateContent","countTokens"]}]}"#;
const ACCEPTED: &str = r#"{"ok":true}"#;
const OPENAI_TRANSCRIPTION_RESPONSE: &str =
    r#"{"text":"transcribed","segments":[],"provider_extension":{"opaque":true}}"#;
const OPENAI_VIDEO_RESPONSE: &str =
    r#"{"id":"video_sanitized","object":"video","status":"in_progress","progress":42}"#;
const OPENAI_VIDEO_DELETE_RESPONSE: &str =
    r#"{"id":"video_sanitized","object":"video.deleted","deleted":true}"#;
const OPENAI_VIDEO_CONTENT: &str = "VIDEO_BYTES";
const OPENAI_COMPACTED_RESPONSE: &str = r#"{"id":"resp_compact_sanitized","created_at":1787270400,"object":"response.compaction","output":[{"id":"msg_sanitized","type":"message","status":"completed","role":"user","content":[{"type":"input_text","text":"sanitized"}]},{"id":"cmp_sanitized","type":"compaction","encrypted_content":"sanitized-encrypted-content"}],"usage":{"input_tokens":12,"input_tokens_details":{"cached_tokens":0},"output_tokens":4,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":16}}"#;
const OPENAI_CLIENT_SECRET_RESPONSE: &str = r#"{"value":"ek_sanitized","expires_at":1787271000,"session":{"id":"sess_sanitized","object":"realtime.session","type":"realtime"}}"#;
const OPENAI_LEGACY_SESSION_RESPONSE: &str = r#"{"client_secret":{"value":"ek_sanitized","expires_at":1787270460},"model":"gpt-4o-realtime-preview"}"#;
const OPENAI_TRANSCRIPTION_SESSION_RESPONSE: &str = r#"{"client_secret":{"value":"ek_sanitized","expires_at":1787271000},"input_audio_format":"pcm16"}"#;

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
                    path: "/v1/completions",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "prompt"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/embeddings",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "input"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/files",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/files",
                    content_type: Some("multipart/form-data"),
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/files/*/content",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/files/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "DELETE",
                    path: "/v1/files/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/batches",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/batches",
                    content_type: Some("application/json"),
                    required_body_fields: &["input_file_id", "endpoint", "completion_window"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/batches/*/cancel",
                    content_type: None,
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/batches/*",
                    content_type: None,
                    required_body_fields: &[],
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
                    response: OPENAI_COMPACTED_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/images/generations",
                    content_type: Some("application/json"),
                    required_body_fields: &["prompt"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/images/edits",
                    content_type: Some("multipart/form-data"),
                    required_body_fields: &[],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/audio/transcriptions",
                    content_type: Some("multipart/form-data"),
                    required_body_fields: &[],
                    response: OPENAI_TRANSCRIPTION_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/videos",
                    content_type: Some("multipart/form-data"),
                    required_body_fields: &[],
                    response: OPENAI_VIDEO_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/videos/edits",
                    content_type: Some("multipart/form-data"),
                    required_body_fields: &[],
                    response: OPENAI_VIDEO_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/videos/extensions",
                    content_type: Some("multipart/form-data"),
                    required_body_fields: &[],
                    response: OPENAI_VIDEO_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/videos/*/remix",
                    content_type: Some("application/json"),
                    required_body_fields: &["prompt"],
                    response: OPENAI_VIDEO_RESPONSE,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/videos/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: OPENAI_VIDEO_RESPONSE,
                },
                ProviderRoute {
                    method: "GET",
                    path: "/v1/videos/*/content",
                    content_type: None,
                    required_body_fields: &[],
                    response: OPENAI_VIDEO_CONTENT,
                },
                ProviderRoute {
                    method: "DELETE",
                    path: "/v1/videos/*",
                    content_type: None,
                    required_body_fields: &[],
                    response: OPENAI_VIDEO_DELETE_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/client_secrets",
                    content_type: Some("application/json"),
                    required_body_fields: &[],
                    response: OPENAI_CLIENT_SECRET_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/sessions",
                    content_type: Some("application/json"),
                    required_body_fields: &[],
                    response: OPENAI_LEGACY_SESSION_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/transcription_sessions",
                    content_type: Some("application/json"),
                    required_body_fields: &[],
                    response: OPENAI_TRANSCRIPTION_SESSION_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/calls/*/accept",
                    content_type: Some("application/json"),
                    required_body_fields: &["type"],
                    response: "",
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/calls/*/reject",
                    content_type: Some("application/json"),
                    required_body_fields: &[],
                    response: "",
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/calls/*/refer",
                    content_type: Some("application/json"),
                    required_body_fields: &["target_uri"],
                    response: "",
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/realtime/calls/*/hangup",
                    content_type: None,
                    required_body_fields: &[],
                    response: "",
                },
            ],
        }
    }

    /// Kimi Open Platform: bearer credential and OpenAI-compatible model/chat paths.
    #[must_use]
    pub const fn kimi() -> Self {
        Self {
            name: "kimi",
            credential_header: "authorization",
            credential_prefix: "Bearer ",
            required_headers: &[],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/v1/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: KIMI_MODELS,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/chat/completions",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "messages"],
                    response: ACCEPTED,
                },
            ],
        }
    }

    /// Vertex AI: Google access token and project/location publisher-model paths.
    #[must_use]
    pub const fn vertex() -> Self {
        Self {
            name: "vertex",
            credential_header: "authorization",
            credential_prefix: "Bearer ",
            required_headers: &[],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/v1/projects/test-project/locations/us-central1/publishers/google/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: VERTEX_MODELS,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent",
                    content_type: Some("application/json"),
                    required_body_fields: &["contents"],
                    response: VERTEX_GENERATE_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:streamGenerateContent",
                    content_type: Some("application/json"),
                    required_body_fields: &["contents"],
                    response: VERTEX_STREAM_RESPONSE,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/projects/test-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:countTokens",
                    content_type: Some("application/json"),
                    required_body_fields: &["contents"],
                    response: ACCEPTED,
                },
            ],
        }
    }

    /// Antigravity pinned compatibility surface: bearer credential and internal paths.
    #[must_use]
    pub const fn antigravity() -> Self {
        Self {
            name: "antigravity",
            credential_header: "authorization",
            credential_prefix: "Bearer ",
            required_headers: &[("user-agent", "antigravity/hub/sanitized darwin/arm64")],
            routes: &[
                ProviderRoute {
                    method: "POST",
                    path: "/v1internal:generateContent",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "request"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1internal:streamGenerateContent",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "request"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1internal:countTokens",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "request"],
                    response: ACCEPTED,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1internal:fetchAvailableModels",
                    content_type: Some("application/json"),
                    required_body_fields: &[],
                    response: ANTIGRAVITY_MODELS,
                },
            ],
        }
    }

    /// Explicit OpenAI-compatible vendor with nonstandard paths and auth header.
    #[must_use]
    pub const fn compatible() -> Self {
        Self {
            name: "compatible",
            credential_header: "x-provider-token",
            credential_prefix: "Token ",
            required_headers: &[],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/vendor/v2/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: COMPATIBLE_MODELS,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/vendor/v2/generate",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "messages"],
                    response: ACCEPTED,
                },
            ],
        }
    }

    /// xAI: bearer credential and the explicitly documented Compact endpoint.
    #[must_use]
    pub const fn xai() -> Self {
        Self {
            name: "xai",
            credential_header: "authorization",
            credential_prefix: "Bearer ",
            required_headers: &[],
            routes: &[
                ProviderRoute {
                    method: "GET",
                    path: "/v1/models",
                    content_type: None,
                    required_body_fields: &[],
                    response: XAI_MODELS,
                },
                ProviderRoute {
                    method: "POST",
                    path: "/v1/responses/compact",
                    content_type: Some("application/json"),
                    required_body_fields: &["model", "input"],
                    response: OPENAI_COMPACTED_RESPONSE,
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
                let content_type = if request.path.ends_with("/content") {
                    "video/mp4"
                } else {
                    "application/json"
                };
                respond(&mut stream, 200, "OK", body, content_type).await;
                log.accepted.push(request);
            }
            Err(rejection) => {
                respond(
                    &mut stream,
                    rejection.status,
                    rejection.reason_phrase,
                    "{}",
                    "application/json",
                )
                .await;
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
    for (name, value) in openai_route_headers(route.path) {
        if request.header(name) != Some(*value) {
            return Err(Rejection::new(
                400,
                "Bad Request",
                format!("{name} must be {value}"),
            ));
        }
    }
    if let Some(query) = &request.query {
        let documented_stream_query =
            route.path.ends_with(":streamGenerateContent") && query == "alt=sse";
        let documented_video_query = route.path == "/v1/videos/*/content"
            && matches!(
                query.as_str(),
                "variant=video" | "variant=thumbnail" | "variant=spritesheet"
            );
        if !documented_stream_query && !documented_video_query {
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

fn openai_route_headers(path: &str) -> &'static [(&'static str, &'static str)] {
    match path {
        "/v1/realtime/sessions" | "/v1/realtime/transcription_sessions" => {
            &[("openai-beta", "assistants=v2")]
        }
        "/v1/realtime/calls/*/accept"
        | "/v1/realtime/calls/*/reject"
        | "/v1/realtime/calls/*/refer"
        | "/v1/realtime/calls/*/hangup" => &[("accept", "*/*")],
        "/v1/videos/*/content" => &[("accept", "application/binary")],
        _ => &[],
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    content_type: &str,
) {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
