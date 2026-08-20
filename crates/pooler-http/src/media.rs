//! Request-side semantic adapter for bounded raw and multipart media.
//!
//! The adapter validates media with Pooler's protocol codecs and derives the
//! capabilities used by target selection. It deliberately keeps the original
//! content type and body bytes unchanged; media responses remain opaque.

use http::{header, HeaderMap};
use pooler_config::RoutePlan;
use pooler_core::{BodyMode, Capability};
use pooler_protocol::{
    ContentPart, DecodedMultipartMedia, MediaCodec, MediaCodecError, MediaLimits,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    BoxError, ProxyBody, SelectionContext, SemanticAdapter, SemanticRequestBody,
    SemanticResponseBody,
};

/// Decoder identifier for a bounded raw image, audio, or file request.
pub const MEDIA_BINARY_DECODER: &str = "decode.media.binary";
/// Decoder identifier for a bounded `multipart/form-data` request.
pub const MEDIA_MULTIPART_DECODER: &str = "decode.media.multipart";

/// Request-side adapter for media routes with opaque upstream responses.
#[derive(Clone, Copy, Debug, Default)]
pub struct MediaSemanticAdapter {
    limits: MediaLimits,
}

impl MediaSemanticAdapter {
    /// Construct an adapter with explicit multipart parser bounds.
    ///
    /// Route body/header limits are always applied as stricter upper bounds.
    #[must_use]
    pub const fn new(limits: MediaLimits) -> Self {
        Self { limits }
    }

    fn inspect(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, MediaSemanticAdapterError> {
        let decoder = decoder(route).ok_or(MediaSemanticAdapterError::UnsupportedRoute)?;
        let content_type = one_content_type(headers)?;
        let limits = self.effective_limits(route);
        let mut context = SelectionContext::default();

        match decoder {
            MEDIA_BINARY_DECODER => {
                if media_type_essence(content_type).eq_ignore_ascii_case("multipart/form-data") {
                    return Err(MediaSemanticAdapterError::UnexpectedMultipart);
                }
                let part = MediaCodec::decode_binary(body, content_type, None, limits)?;
                require_content_capabilities(&mut context, &part);
            }
            MEDIA_MULTIPART_DECODER => {
                let decoded = MediaCodec::decode_multipart(body, content_type, limits)?;
                require_multipart_capabilities(&mut context, &decoded);
            }
            _ => return Err(MediaSemanticAdapterError::UnsupportedRoute),
        }
        context.with_codec(decoder);
        Ok(context)
    }

    fn effective_limits(&self, route: &RoutePlan) -> MediaLimits {
        let max_body_bytes = self
            .limits
            .max_body_bytes
            .min(usize_limit(route.limits().max_request_body_bytes));
        MediaLimits {
            max_body_bytes,
            max_part_bytes: self.limits.max_part_bytes.min(max_body_bytes),
            max_parts: self.limits.max_parts,
            max_header_bytes: self
                .limits
                .max_header_bytes
                .min(usize_limit(route.limits().max_header_bytes)),
            max_headers_per_part: self
                .limits
                .max_headers_per_part
                .min(usize_limit(u64::from(route.limits().max_header_count))),
        }
    }
}

impl SemanticAdapter for MediaSemanticAdapter {
    fn supports(&self, route: &RoutePlan) -> bool {
        decoder(route).is_some()
    }

    fn encode_request(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SemanticRequestBody, BoxError> {
        self.inspect(route, headers, body)
            .map_err(|error| Box::new(error) as BoxError)?;
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .expect("validated content type remains present")
            .clone();
        Ok(SemanticRequestBody {
            body: body.to_vec(),
            content_type,
            response_hint: crate::SemanticResponseHint::default(),
        })
    }

    fn selection_context(
        &self,
        route: &RoutePlan,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SelectionContext, BoxError> {
        self.inspect(route, headers, body)
            .map_err(|error| Box::new(error) as BoxError)
    }

    fn decode_response(
        &self,
        _route: &RoutePlan,
        _body: ProxyBody,
        _cancellation: CancellationToken,
    ) -> Result<SemanticResponseBody, BoxError> {
        Err(Box::new(MediaSemanticAdapterError::OpaqueResponseRequired))
    }
}

/// Errors returned while validating a request-side media route.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MediaSemanticAdapterError {
    /// The route does not declare one of the media decoder contracts.
    #[error("media adapter requires semantic ingress and an opaque response")]
    UnsupportedRoute,
    /// Media requests must carry one unambiguous content type.
    #[error("media request requires exactly one valid content-type header")]
    InvalidContentTypeHeader,
    /// Multipart bodies must use the multipart decoder.
    #[error("raw media decoder does not accept multipart/form-data")]
    UnexpectedMultipart,
    /// The bounded media codec rejected the request.
    #[error("invalid media request: {0}")]
    Codec(#[from] MediaCodecError),
    /// This request-side adapter intentionally leaves responses opaque.
    #[error("media semantic routes require opaque responses")]
    OpaqueResponseRequired,
}

fn decoder(route: &RoutePlan) -> Option<&str> {
    if route.ingress().mode() != BodyMode::Semantic
        || route.response().mode() != BodyMode::Opaque
        || route.ingress().framing().is_some()
    {
        return None;
    }
    match route.ingress().decoder()? {
        MEDIA_BINARY_DECODER => Some(MEDIA_BINARY_DECODER),
        MEDIA_MULTIPART_DECODER => Some(MEDIA_MULTIPART_DECODER),
        _ => None,
    }
}

fn one_content_type(headers: &HeaderMap) -> Result<&str, MediaSemanticAdapterError> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .ok_or(MediaSemanticAdapterError::InvalidContentTypeHeader)?;
    value
        .to_str()
        .map_err(|_| MediaSemanticAdapterError::InvalidContentTypeHeader)
}

fn media_type_essence(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

fn require_multipart_capabilities(context: &mut SelectionContext, decoded: &DecodedMultipartMedia) {
    for part in &decoded.parts {
        require_content_capabilities(context, &part.content);
    }
}

fn require_content_capabilities(context: &mut SelectionContext, content: &ContentPart) {
    match content {
        ContentPart::Text { .. } => context.require(Capability::Text),
        ContentPart::Image { .. } => context.require(Capability::Images),
        ContentPart::Audio { .. } => {
            context.require(Capability::Audio);
            context.require(Capability::InputAudio);
        }
        ContentPart::File { .. } => context.require(Capability::Files),
        ContentPart::Reasoning(_)
        | ContentPart::ToolCall(_)
        | ContentPart::ToolResult(_)
        | ContentPart::Provider { .. } => {}
    }
}

fn usize_limit(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}
