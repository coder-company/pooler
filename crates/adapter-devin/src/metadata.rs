//! Devin authentication, client metadata, and model-discovery codecs.

use crate::{
    connect::{decode_proto_with_gzip_fallback, ConnectError, ConnectLimits},
    proto::{
        ClientModelConfig, GetCliModelConfigsRequest, GetCliModelConfigsResponse,
        GetUserJwtRequest, GetUserJwtResponse, Metadata,
    },
};
use prost::Message;
use std::collections::BTreeMap;
use thiserror::Error;

/// Devin's model discovery endpoint.
pub const DEVIN_MODELS_PATH: &str = "/exa.api_server_pb.ApiServerService/GetCliModelConfigs";
/// Devin's user-JWT endpoint.
pub const DEVIN_AUTH_PATH: &str = "/exa.auth_pb.AuthService/GetUserJwt";
/// Devin's streamed chat endpoint.
pub const DEVIN_CHAT_PATH: &str = "/exa.api_server_pb.ApiServerService/GetChatMessage";
/// Wire content type for unary Devin protobuf requests.
pub const DEVIN_PROTO_CONTENT_TYPE: &str = "application/proto";
/// Wire content type for Connect protobuf requests.
pub const DEVIN_CONNECT_CONTENT_TYPE: &str = "application/connect+proto";
/// Session-token prefix required by the Devin metadata contract.
pub const DEVIN_SESSION_TOKEN_PREFIX: &str = "devin-session-token$";
/// Default client IDE version observed in the local bridge.
pub const DEVIN_IDE_VERSION: &str = "3.2.23";
/// Default client extension version observed in the local bridge.
pub const DEVIN_EXTENSION_VERSION: &str = "1.48.2";
/// Default stop patterns observed in the local bridge.
pub const DEVIN_DEFAULT_STOP_PATTERNS: [&str; 5] = [
    "<|user|>",
    "<|bot|>",
    "<|context_request|>",
    "<|endoftext|>",
    "<|end_of_turn|>",
];

/// Optional client identity fields sent to Devin.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DevinClientMetadata {
    /// Client IDE name.
    pub ide_name: Option<String>,
    /// Client IDE version.
    pub ide_version: Option<String>,
    /// Client IDE type.
    pub ide_type: Option<String>,
    /// Client extension name.
    pub extension_name: Option<String>,
    /// Client extension version.
    pub extension_version: Option<String>,
    /// Client locale.
    pub locale: Option<String>,
}

/// Builds the protobuf metadata used by all known Devin metadata handlers.
///
/// The token arguments are intentionally explicit because model discovery and
/// JWT exchange use the session token in `api_key`, while chat requests carry
/// both values.  Callers must keep this value out of logs and conversion
/// reports.
#[must_use]
pub fn metadata(
    api_key: &str,
    user_jwt: &str,
    client_metadata: Option<&DevinClientMetadata>,
) -> Metadata {
    let client = client_metadata.cloned().unwrap_or_default();
    Metadata {
        ide_name: client.ide_name.unwrap_or_else(|| "windsurf".to_owned()),
        ide_version: client
            .ide_version
            .unwrap_or_else(|| DEVIN_IDE_VERSION.to_owned()),
        ide_type: client.ide_type.unwrap_or_default(),
        extension_name: client
            .extension_name
            .unwrap_or_else(|| "windsurf".to_owned()),
        extension_version: client
            .extension_version
            .unwrap_or_else(|| DEVIN_EXTENSION_VERSION.to_owned()),
        api_key: api_key.to_owned(),
        locale: client.locale.unwrap_or_else(|| "en".to_owned()),
        user_jwt: user_jwt.to_owned(),
        ..Default::default()
    }
}

/// Adds the Devin session-token prefix exactly once.
#[must_use]
pub fn normalize_devin_session_token(token: Option<&str>) -> String {
    let token = token.unwrap_or_default().trim();
    if token.is_empty() {
        return String::new();
    }
    if token.starts_with(DEVIN_SESSION_TOKEN_PREFIX) {
        token.to_owned()
    } else {
        format!("{DEVIN_SESSION_TOKEN_PREFIX}{token}")
    }
}

/// User-JWT metadata returned by the auth endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthMetadata {
    /// User JWT used by chat requests.
    pub user_jwt: String,
    /// Optional custom chat API base URL.
    pub custom_api_server_url: Option<String>,
}

/// A normalized model advertised by Devin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevinModel {
    /// Stable model identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Provider identity.
    pub provider: &'static str,
    /// Base URL used for this model's provider route.
    pub base_url: String,
    /// Supported input modalities.
    pub input: Vec<DevinInput>,
    /// Whether model tools are supported by the bridge.
    pub supports_tools: bool,
    /// Whether reasoning/thinking is supported.
    pub reasoning: bool,
    /// Context window hint.
    pub context_window: i32,
    /// Maximum output token hint.
    pub max_tokens: i32,
}

/// Input modality advertised by a Devin model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevinInput {
    /// Text input.
    Text,
    /// Image input.
    Image,
}

/// Metadata codec errors.
#[derive(Debug, Error)]
pub enum MetadataError {
    /// Protobuf or gzip decoding failed.
    #[error("invalid Devin metadata protobuf: {0}")]
    Connect(#[from] ConnectError),
    /// Auth succeeded but did not return a usable JWT.
    #[error("Devin auth returned an empty user JWT")]
    EmptyUserJwt,
}

/// Builds a model discovery request body.
#[must_use]
pub fn encode_model_request(
    token: Option<&str>,
    client_metadata: Option<&DevinClientMetadata>,
) -> Vec<u8> {
    GetCliModelConfigsRequest {
        metadata: Some(metadata(
            &normalize_devin_session_token(token),
            "",
            client_metadata,
        )),
    }
    .encode_to_vec()
}

/// Decodes a model discovery response, accepting an optional gzip body.
pub fn decode_model_response(
    payload: &[u8],
    base_url: &str,
    limits: ConnectLimits,
) -> Result<Vec<DevinModel>, MetadataError> {
    let response = decode_proto_with_gzip_fallback::<GetCliModelConfigsResponse>(payload, limits)?;
    Ok(normalize_models(&response.client_model_configs, base_url))
}

/// Builds the user-JWT request body.
#[must_use]
pub fn encode_auth_request(
    token: Option<&str>,
    client_metadata: Option<&DevinClientMetadata>,
) -> Vec<u8> {
    GetUserJwtRequest {
        metadata: Some(metadata(
            &normalize_devin_session_token(token),
            "",
            client_metadata,
        )),
    }
    .encode_to_vec()
}

/// Decodes the user-JWT response, accepting an optional gzip body.
pub fn decode_auth_response(
    payload: &[u8],
    limits: ConnectLimits,
) -> Result<AuthMetadata, MetadataError> {
    let response = decode_proto_with_gzip_fallback::<GetUserJwtResponse>(payload, limits)?;
    if response.user_jwt.trim().is_empty() {
        return Err(MetadataError::EmptyUserJwt);
    }
    let custom = response.custom_api_server_url.trim();
    Ok(AuthMetadata {
        user_jwt: response.user_jwt,
        custom_api_server_url: (!custom.is_empty()).then(|| trim_trailing_slashes(custom)),
    })
}

/// Normalizes enabled, named Devin model declarations deterministically.
#[must_use]
pub fn normalize_models(configs: &[ClientModelConfig], base_url: &str) -> Vec<DevinModel> {
    const DEFAULT_CONTEXT_WINDOW: i32 = 200_000;
    const DEFAULT_MAX_TOKENS: i32 = 64_000;

    let mut models = BTreeMap::new();
    for config in configs.iter().filter(|config| !config.disabled) {
        let id = config.model_uid.trim();
        if !id.is_empty() {
            let context_window = if config.max_tokens > 0 {
                config.max_tokens
            } else {
                DEFAULT_CONTEXT_WINDOW
            };
            let max_tokens = if config.max_tokens > 0 {
                config.max_tokens.min(DEFAULT_MAX_TOKENS)
            } else {
                DEFAULT_MAX_TOKENS
            };
            let model = DevinModel {
                id: id.to_owned(),
                name: if config.label.trim().is_empty() {
                    id.to_owned()
                } else {
                    config.label.trim().to_owned()
                },
                provider: "devin",
                base_url: base_url.to_owned(),
                input: if config.supports_images {
                    vec![DevinInput::Text, DevinInput::Image]
                } else {
                    vec![DevinInput::Text]
                },
                supports_tools: true,
                reasoning: supports_thinking(config),
                context_window,
                max_tokens,
            };
            // The local widevin bridge uses an insertion-ordered map,
            // whose insert operation makes the last declaration win.
            models.insert(id.to_owned(), model);
        }
    }
    models.into_values().collect()
}

fn supports_thinking(config: &ClientModelConfig) -> bool {
    let label = config.label.to_ascii_lowercase();
    if contains_ascii_word_phrase(&label, "no thinking") {
        return false;
    }
    config
        .model_info
        .as_ref()
        .and_then(|info| info.model_features.as_ref())
        .is_some_and(|features| features.supports_thinking)
        || [
            "think",
            "thinking",
            "minimal",
            "high",
            "medium",
            "low",
            "xhigh",
            "max",
            "reasoning",
        ]
        .iter()
        .any(|term| contains_ascii_word_phrase(&label, term))
}

fn contains_ascii_word_phrase(value: &str, phrase: &str) -> bool {
    value.match_indices(phrase).any(|(start, matched)| {
        let before = value[..start].chars().next_back();
        let after = value[start + matched.len()..].chars().next();
        before.is_none_or(|character| !is_ascii_word(character))
            && after.is_none_or(|character| !is_ascii_word(character))
    })
}

fn is_ascii_word(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn trim_trailing_slashes(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        decode_auth_response, encode_model_request, metadata, normalize_devin_session_token,
        normalize_models, DevinClientMetadata, DevinInput, DEVIN_SESSION_TOKEN_PREFIX,
    };
    use crate::{connect::ConnectLimits, proto};
    use prost::Message;

    #[test]
    fn metadata_defaults_and_identity_override_match_local_bridge() {
        let value = metadata(
            "token",
            "jwt",
            Some(&DevinClientMetadata {
                ide_name: Some("devin".into()),
                ide_type: Some("local".into()),
                ..Default::default()
            }),
        );
        assert_eq!(value.ide_name, "devin");
        assert_eq!(value.ide_type, "local");
        assert_eq!(value.extension_name, "windsurf");
        assert_eq!(value.api_key, "token");
    }

    #[test]
    fn token_prefix_is_added_once_and_empty_is_absent() {
        assert_eq!(normalize_devin_session_token(None), "");
        assert_eq!(
            normalize_devin_session_token(Some("raw")),
            format!("{DEVIN_SESSION_TOKEN_PREFIX}raw")
        );
        assert_eq!(
            normalize_devin_session_token(Some("devin-session-token$raw")),
            "devin-session-token$raw"
        );
    }

    #[test]
    fn model_response_normalization_filters_and_sorts() {
        let models = normalize_models(
            &[
                proto::ClientModelConfig {
                    model_uid: " model-a ".into(),
                    label: "Model Thinking".into(),
                    supports_images: true,
                    max_tokens: 1_000,
                    ..Default::default()
                },
                proto::ClientModelConfig {
                    model_uid: "disabled".into(),
                    disabled: true,
                    ..Default::default()
                },
                proto::ClientModelConfig {
                    model_uid: "model-a".into(),
                    label: "Model A Thinking Replacement".into(),
                    max_tokens: 2_000,
                    ..Default::default()
                },
            ],
            "https://server.example/",
        );
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "model-a");
        assert_eq!(models[0].name, "Model A Thinking Replacement");
        assert_eq!(models[0].max_tokens, 2_000);
        assert_eq!(models[0].input, vec![DevinInput::Text]);
        assert!(models[0].reasoning);
    }

    #[test]
    fn auth_response_accepts_gzip_fallback_and_rejects_empty_jwt() {
        let bytes = proto::GetUserJwtResponse {
            user_jwt: "jwt".into(),
            custom_api_server_url: "https://chat.example/".into(),
        }
        .encode_to_vec();
        let result = decode_auth_response(&bytes, ConnectLimits::default()).expect("auth");
        assert_eq!(
            result.custom_api_server_url.as_deref(),
            Some("https://chat.example")
        );
        let empty = proto::GetUserJwtResponse::default().encode_to_vec();
        assert!(decode_auth_response(&empty, ConnectLimits::default()).is_err());
        let request = encode_model_request(Some("raw"), None);
        let request =
            proto::GetCliModelConfigsRequest::decode(request.as_slice()).expect("request");
        assert_eq!(
            request.metadata.expect("metadata").api_key,
            "devin-session-token$raw"
        );
    }
}
