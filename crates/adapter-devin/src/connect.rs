//! Devin framing helpers backed by Pooler's shared Connect codec.
//!
//! This module keeps only adapter-specific stream and protobuf helpers. The
//! envelope parser, gzip implementation, flags, and bounds live in
//! [`pooler_protocol`], so every semantic adapter uses one wire contract.

use futures_core::Stream;
use futures_util::StreamExt;
use pooler_protocol::{ConnectCompression, ConnectEncoder, ConnectEnvelope};
use prost::Message;
use serde_json::Value;
use std::pin::Pin;

pub use pooler_protocol::{
    ConnectDecoder, ConnectEnvelope as ConnectFrame, ConnectError, ConnectLimits,
    CONNECT_FLAG_COMPRESSED as CONNECT_COMPRESSED_FLAG,
    CONNECT_FLAG_END_STREAM as CONNECT_END_STREAM_FLAG,
    DEFAULT_CONNECT_MAX_DECOMPRESSED_BYTES as MAX_CONNECT_DECOMPRESSED_PAYLOAD,
    DEFAULT_CONNECT_MAX_FRAME_BYTES as MAX_CONNECT_FRAME_PAYLOAD,
};

/// Encodes one Devin Connect envelope using Pooler's shared gzip and bounds.
pub fn encode_connect_frame(
    payload: &[u8],
    compress: bool,
    end_stream: bool,
) -> Result<Vec<u8>, ConnectError> {
    encode_connect_frame_with_limits(payload, compress, end_stream, ConnectLimits::default())
}

/// Encodes one Devin Connect envelope with explicit bounds.
pub fn encode_connect_frame_with_limits(
    payload: &[u8],
    compress: bool,
    end_stream: bool,
    limits: ConnectLimits,
) -> Result<Vec<u8>, ConnectError> {
    if compress && end_stream {
        return Err(ConnectError::CompressedEndStream);
    }
    let compression = if compress {
        ConnectCompression::Gzip
    } else {
        ConnectCompression::Identity
    };
    let envelope = if end_stream {
        ConnectEnvelope::end_stream(payload.to_vec())
    } else if compress {
        ConnectEnvelope::compressed_data(payload.to_vec())
    } else {
        ConnectEnvelope::data(payload.to_vec())
    };
    ConnectEncoder::with_compression(limits, compression).encode(&envelope)
}

/// Decodes arbitrary transport chunks with the shared Connect parser.
pub fn decode_connect_frames<S>(
    chunks: S,
) -> Pin<Box<dyn Stream<Item = Result<ConnectFrame, ConnectError>> + Send>>
where
    S: Stream<Item = Result<Vec<u8>, ConnectError>> + Send + 'static,
{
    decode_connect_frames_with_limits(chunks, ConnectLimits::default())
}

/// Decodes arbitrary transport chunks under explicit shared bounds.
pub fn decode_connect_frames_with_limits<S>(
    chunks: S,
    limits: ConnectLimits,
) -> Pin<Box<dyn Stream<Item = Result<ConnectFrame, ConnectError>> + Send>>
where
    S: Stream<Item = Result<Vec<u8>, ConnectError>> + Send + 'static,
{
    Box::pin(async_stream::stream! {
        futures_util::pin_mut!(chunks);
        let mut decoder = ConnectDecoder::with_gzip(limits);
        while let Some(chunk) = chunks.next().await {
            match chunk {
                Ok(chunk) => match decoder.feed(&chunk) {
                    Ok(frames) => {
                        for frame in frames {
                            yield Ok(frame);
                        }
                    }
                    Err(error) => {
                        yield Err(error);
                        return;
                    }
                },
                Err(error) => {
                    yield Err(error);
                    return;
                }
            }
        }
        if let Err(error) = decoder.finish() {
            yield Err(error);
        }
    })
}

/// Decodes a protobuf message from an uncompressed or gzip-compressed body.
pub fn decode_proto_with_gzip_fallback<M>(
    payload: &[u8],
    limits: ConnectLimits,
) -> Result<M, ConnectError>
where
    M: Message + Default,
{
    let original = M::decode(payload).map_err(|error| error.to_string());
    match original {
        Ok(message) => Ok(message),
        Err(original_error) => {
            let decoded =
                pooler_protocol::decode_gzip_payload(payload, limits.max_decompressed_bytes)
                    .map_err(|error| ConnectError::InvalidGzip {
                        message: format!("protobuf decode failed ({original_error}); {error}"),
                    })?;
            M::decode(decoded.as_slice()).map_err(|error| ConnectError::InvalidGzip {
                message: format!("invalid protobuf after gzip decode: {error}"),
            })
        }
    }
}

/// Extracts a structured Connect trailer error without exposing its payload.
pub fn read_connect_trailer_error(payload: &[u8]) -> Option<String> {
    let parsed = serde_json::from_slice::<Value>(payload).ok()?;
    let error = parsed.get("error")?;
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    (!code.is_empty() || !message.is_empty()).then(|| {
        if code.is_empty() {
            format!("Devin stream error: {message}")
        } else {
            format!("Devin stream error {code}: {message}")
        }
    })
}
