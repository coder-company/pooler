//! Incremental, bounded ConnectRPC envelope framing.
//!
//! A Connect envelope consists of a flags byte, a four-byte big-endian
//! payload length, and that many payload bytes.  The decoder accepts arbitrary
//! transport chunks and retains only the current envelope.  The payload
//! returned to callers is always decompressed; the compression bit remains on
//! the envelope so a caller can preserve the wire representation when it is
//! encoded again.

use std::{
    fmt,
    io::{self, Cursor, Read, Write},
};

use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};
use thiserror::Error;

/// Number of bytes in a Connect envelope header.
pub const CONNECT_ENVELOPE_HEADER_BYTES: usize = 5;
/// Connect's data-envelope gzip/compression flag.
pub const CONNECT_FLAG_COMPRESSED: u8 = 0x01;
/// Connect's end-stream envelope flag.
pub const CONNECT_FLAG_END_STREAM: u8 = 0x02;
/// Flags accepted by this codec. Other bits are reserved by Connect.
pub const CONNECT_ALLOWED_FLAGS: u8 = CONNECT_FLAG_COMPRESSED | CONNECT_FLAG_END_STREAM;
/// Default maximum number of bytes in one wire envelope payload.
pub const DEFAULT_CONNECT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum number of bytes after gzip decompression.
pub const DEFAULT_CONNECT_MAX_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

/// Compression negotiated for a Connect stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnectCompression {
    /// No message compression was negotiated.
    #[default]
    Identity,
    /// Gzip message compression was negotiated.
    Gzip,
}

/// Bounds applied to each Connect envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectLimits {
    /// Maximum serialized payload bytes carried by one envelope.
    pub max_frame_bytes: usize,
    /// Maximum payload bytes after decompression.
    pub max_decompressed_bytes: usize,
}

impl ConnectLimits {
    /// Creates explicit wire and decompressed payload bounds.
    #[must_use]
    pub const fn new(max_frame_bytes: usize, max_decompressed_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            max_decompressed_bytes,
        }
    }
}

impl Default for ConnectLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_CONNECT_MAX_FRAME_BYTES,
            DEFAULT_CONNECT_MAX_DECOMPRESSED_BYTES,
        )
    }
}

/// One decoded Connect envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectEnvelope {
    flags: u8,
    /// Decompressed envelope payload.
    pub payload: Vec<u8>,
}

impl ConnectEnvelope {
    /// Creates an envelope with validated Connect flags.
    pub fn new(flags: u8, payload: impl Into<Vec<u8>>) -> Result<Self, ConnectError> {
        validate_flags(flags)?;
        Ok(Self {
            flags,
            payload: payload.into(),
        })
    }

    /// Creates an uncompressed data envelope.
    #[must_use]
    pub fn data(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            flags: 0,
            payload: payload.into(),
        }
    }

    /// Creates a data envelope that will be gzip-compressed by the encoder.
    #[must_use]
    pub fn compressed_data(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            flags: CONNECT_FLAG_COMPRESSED,
            payload: payload.into(),
        }
    }

    /// Creates an uncompressed end-stream envelope.
    #[must_use]
    pub fn end_stream(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            flags: CONNECT_FLAG_END_STREAM,
            payload: payload.into(),
        }
    }

    /// Returns the raw Connect flags byte.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns whether the envelope was marked compressed on the wire.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & CONNECT_FLAG_COMPRESSED != 0
    }

    /// Returns whether the envelope terminates the stream.
    #[must_use]
    pub const fn is_end_stream(&self) -> bool {
        self.flags & CONNECT_FLAG_END_STREAM != 0
    }

    /// Consumes the envelope and returns its decoded payload.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Returns the decompressed envelope payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Errors returned by bounded Connect framing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConnectError {
    /// A flags byte contains reserved bits.
    #[error("invalid Connect envelope flags 0x{flags:02x}")]
    InvalidFlags { flags: u8 },
    /// Connect does not permit compression on an end-stream envelope.
    #[error("Connect end-stream envelopes cannot be compressed")]
    CompressedEndStream,
    /// A compressed envelope arrived without a matching negotiated codec.
    #[error("Connect envelope uses compression that was not negotiated")]
    CompressionNotNegotiated,
    /// A wire envelope exceeds the configured payload bound.
    #[error("Connect envelope payload exceeds the {limit} byte frame limit (observed {observed})")]
    FrameTooLarge { observed: usize, limit: usize },
    /// A decoded payload exceeds the configured decompressed bound.
    #[error(
        "Connect envelope decompressed payload exceeds the {limit} byte limit (observed at least {observed})"
    )]
    DecompressedTooLarge { observed: usize, limit: usize },
    /// The transport ended in the middle of an envelope.
    #[error("Connect stream ended with a truncated envelope ({bytes} bytes pending)")]
    Truncated { bytes: usize },
    /// A gzip payload could not be decoded.
    #[error("invalid gzip Connect envelope: {message}")]
    InvalidGzip { message: String },
    /// A decoded end-stream envelope was followed by more data.
    #[error("Connect stream contains an envelope after end-stream")]
    AfterEndStream,
}

/// Incremental Connect envelope decoder.
#[derive(Debug)]
pub struct ConnectDecoder {
    limits: ConnectLimits,
    compression: ConnectCompression,
    pending: Vec<u8>,
    expected_payload_bytes: Option<usize>,
    ended: bool,
}

impl Default for ConnectDecoder {
    fn default() -> Self {
        Self::new(ConnectLimits::default())
    }
}

impl ConnectDecoder {
    /// Creates an identity-compression decoder.
    #[must_use]
    pub fn new(limits: ConnectLimits) -> Self {
        Self::with_compression(limits, ConnectCompression::Identity)
    }

    /// Creates a decoder with an explicitly negotiated compression.
    #[must_use]
    pub fn with_compression(limits: ConnectLimits, compression: ConnectCompression) -> Self {
        Self {
            limits,
            compression,
            pending: Vec::with_capacity(CONNECT_ENVELOPE_HEADER_BYTES),
            expected_payload_bytes: None,
            ended: false,
        }
    }

    /// Creates a decoder with gzip message compression enabled.
    #[must_use]
    pub fn with_gzip(limits: ConnectLimits) -> Self {
        Self::with_compression(limits, ConnectCompression::Gzip)
    }

    /// Returns the decoder's configured bounds.
    #[must_use]
    pub const fn limits(&self) -> ConnectLimits {
        self.limits
    }

    /// Returns the negotiated compression.
    #[must_use]
    pub const fn compression(&self) -> ConnectCompression {
        self.compression
    }

    /// Feeds an arbitrary transport chunk and returns complete envelopes.
    pub fn feed(&mut self, mut chunk: &[u8]) -> Result<Vec<ConnectEnvelope>, ConnectError> {
        let mut envelopes = Vec::new();
        while !chunk.is_empty() {
            if self.ended {
                return Err(ConnectError::AfterEndStream);
            }
            if self.expected_payload_bytes.is_none() {
                let needed = CONNECT_ENVELOPE_HEADER_BYTES - self.pending.len();
                let take = needed.min(chunk.len());
                self.pending.extend_from_slice(&chunk[..take]);
                chunk = &chunk[take..];
                if self.pending.len() < CONNECT_ENVELOPE_HEADER_BYTES {
                    continue;
                }

                let flags = self.pending[0];
                validate_flags(flags)?;
                let payload_bytes = u32::from_be_bytes([
                    self.pending[1],
                    self.pending[2],
                    self.pending[3],
                    self.pending[4],
                ]) as usize;
                if payload_bytes > self.limits.max_frame_bytes {
                    return Err(ConnectError::FrameTooLarge {
                        observed: payload_bytes,
                        limit: self.limits.max_frame_bytes,
                    });
                }
                self.expected_payload_bytes = Some(payload_bytes);
            }

            let expected = self
                .expected_payload_bytes
                .expect("payload length is set after parsing a complete header");
            let total_bytes = CONNECT_ENVELOPE_HEADER_BYTES.checked_add(expected).ok_or(
                ConnectError::FrameTooLarge {
                    observed: expected,
                    limit: self.limits.max_frame_bytes,
                },
            )?;
            let needed = total_bytes - self.pending.len();
            let take = needed.min(chunk.len());
            self.pending.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
            if self.pending.len() < total_bytes {
                continue;
            }

            let flags = self.pending[0];
            let payload = self.pending[CONNECT_ENVELOPE_HEADER_BYTES..].to_vec();
            let payload = decode_payload(payload, flags, self.compression, self.limits)?;
            let envelope = ConnectEnvelope { flags, payload };
            self.ended = envelope.is_end_stream();
            envelopes.push(envelope);
            self.pending.clear();
            self.expected_payload_bytes = None;
        }
        Ok(envelopes)
    }

    /// Feeds one arbitrary transport chunk.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<ConnectEnvelope>, ConnectError> {
        self.feed(chunk)
    }

    /// Signals transport EOF and rejects a partial header or payload.
    pub fn finish(&self) -> Result<(), ConnectError> {
        if self.pending.is_empty() && self.expected_payload_bytes.is_none() {
            Ok(())
        } else {
            Err(ConnectError::Truncated {
                bytes: self.pending.len(),
            })
        }
    }
}

/// Bounded Connect envelope encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectEncoder {
    limits: ConnectLimits,
    compression: ConnectCompression,
}

impl Default for ConnectEncoder {
    fn default() -> Self {
        Self::new(ConnectLimits::default())
    }
}

impl ConnectEncoder {
    /// Creates an identity-compression encoder.
    #[must_use]
    pub const fn new(limits: ConnectLimits) -> Self {
        Self::with_compression(limits, ConnectCompression::Identity)
    }

    /// Creates an encoder with an explicitly negotiated compression.
    #[must_use]
    pub const fn with_compression(limits: ConnectLimits, compression: ConnectCompression) -> Self {
        Self {
            limits,
            compression,
        }
    }

    /// Creates an encoder with gzip message compression enabled.
    #[must_use]
    pub const fn with_gzip(limits: ConnectLimits) -> Self {
        Self::with_compression(limits, ConnectCompression::Gzip)
    }

    /// Returns the encoder's configured bounds.
    #[must_use]
    pub const fn limits(&self) -> ConnectLimits {
        self.limits
    }

    /// Encodes one decoded envelope into its Connect wire representation.
    pub fn encode(&self, envelope: &ConnectEnvelope) -> Result<Vec<u8>, ConnectError> {
        validate_flags(envelope.flags)?;
        if envelope.payload.len() > self.limits.max_decompressed_bytes {
            return Err(ConnectError::DecompressedTooLarge {
                observed: envelope.payload.len(),
                limit: self.limits.max_decompressed_bytes,
            });
        }
        let payload = if envelope.is_compressed() {
            if envelope.is_end_stream() {
                return Err(ConnectError::CompressedEndStream);
            }
            if self.compression != ConnectCompression::Gzip {
                return Err(ConnectError::CompressionNotNegotiated);
            }
            gzip_encode(&envelope.payload, self.limits.max_frame_bytes)?
        } else {
            envelope.payload.clone()
        };
        if payload.len() > self.limits.max_frame_bytes {
            return Err(ConnectError::FrameTooLarge {
                observed: payload.len(),
                limit: self.limits.max_frame_bytes,
            });
        }
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| ConnectError::FrameTooLarge {
                observed: payload.len(),
                limit: self.limits.max_frame_bytes,
            })?;
        let mut encoded = Vec::with_capacity(CONNECT_ENVELOPE_HEADER_BYTES + payload.len());
        encoded.push(envelope.flags);
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }
}

/// Decodes all Connect envelopes in one bounded byte slice.
pub fn decode_connect_envelopes(
    input: &[u8],
    limits: ConnectLimits,
    compression: ConnectCompression,
) -> Result<Vec<ConnectEnvelope>, ConnectError> {
    let mut decoder = ConnectDecoder::with_compression(limits, compression);
    let envelopes = decoder.feed(input)?;
    decoder.finish()?;
    Ok(envelopes)
}

/// Encodes one Connect envelope with explicit bounds and compression.
pub fn encode_connect_envelope(
    envelope: &ConnectEnvelope,
    limits: ConnectLimits,
    compression: ConnectCompression,
) -> Result<Vec<u8>, ConnectError> {
    ConnectEncoder::with_compression(limits, compression).encode(envelope)
}

/// Decompresses one gzip payload under the configured output bound.
pub fn decode_gzip_payload(
    payload: &[u8],
    max_decompressed_bytes: usize,
) -> Result<Vec<u8>, ConnectError> {
    gzip_decode(payload, max_decompressed_bytes)
}

fn validate_flags(flags: u8) -> Result<(), ConnectError> {
    if flags & !CONNECT_ALLOWED_FLAGS != 0 {
        return Err(ConnectError::InvalidFlags { flags });
    }
    if flags & CONNECT_FLAG_COMPRESSED != 0 && flags & CONNECT_FLAG_END_STREAM != 0 {
        return Err(ConnectError::CompressedEndStream);
    }
    Ok(())
}

fn decode_payload(
    payload: Vec<u8>,
    flags: u8,
    compression: ConnectCompression,
    limits: ConnectLimits,
) -> Result<Vec<u8>, ConnectError> {
    if flags & CONNECT_FLAG_COMPRESSED == 0 {
        if payload.len() > limits.max_decompressed_bytes {
            return Err(ConnectError::DecompressedTooLarge {
                observed: payload.len(),
                limit: limits.max_decompressed_bytes,
            });
        }
        return Ok(payload);
    }
    if compression != ConnectCompression::Gzip {
        return Err(ConnectError::CompressionNotNegotiated);
    }
    gzip_decode(&payload, limits.max_decompressed_bytes)
}

fn gzip_encode(payload: &[u8], max_frame_bytes: usize) -> Result<Vec<u8>, ConnectError> {
    let mut encoder = GzEncoder::new(BoundedWriter::new(max_frame_bytes), Compression::default());
    encoder.write_all(payload).map_err(map_gzip_write_error)?;
    let writer = encoder.finish().map_err(map_gzip_write_error)?;
    Ok(writer.into_inner())
}

fn gzip_decode(payload: &[u8], limit: usize) -> Result<Vec<u8>, ConnectError> {
    let mut decoder = GzDecoder::new(Cursor::new(payload));
    let mut decoded = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = decoder
            .read(&mut buffer)
            .map_err(|error| ConnectError::InvalidGzip {
                message: error.to_string(),
            })?;
        if bytes_read == 0 {
            break;
        }
        let observed = decoded.len().saturating_add(bytes_read);
        if observed > limit {
            return Err(ConnectError::DecompressedTooLarge { observed, limit });
        }
        decoded.reserve_exact(bytes_read);
        decoded.extend_from_slice(&buffer[..bytes_read]);
    }
    let reader = decoder.into_inner();
    if reader.position() != payload.len() as u64 {
        return Err(ConnectError::InvalidGzip {
            message: "trailing bytes after gzip member".to_owned(),
        });
    }
    Ok(decoded)
}

fn map_gzip_write_error(error: io::Error) -> ConnectError {
    if error.kind() == io::ErrorKind::WriteZero {
        ConnectError::FrameTooLarge {
            observed: error
                .get_ref()
                .and_then(|source| source.downcast_ref::<FrameLimit>())
                .map_or(usize::MAX, |limit| limit.observed),
            limit: error
                .get_ref()
                .and_then(|source| source.downcast_ref::<FrameLimit>())
                .map_or(0, |limit| limit.limit),
        }
    } else {
        ConnectError::InvalidGzip {
            message: error.to_string(),
        }
    }
}

#[derive(Debug)]
struct FrameLimit {
    observed: usize,
    limit: usize,
}

impl fmt::Display for FrameLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compressed payload exceeds frame limit")
    }
}

impl std::error::Error for FrameLimit {}

#[derive(Debug)]
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let observed = self.bytes.len().saturating_add(bytes.len());
        if observed > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                FrameLimit {
                    observed,
                    limit: self.limit,
                },
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_connect_envelopes, encode_connect_envelope, ConnectCompression, ConnectDecoder,
        ConnectEncoder, ConnectEnvelope, ConnectError, ConnectLimits, CONNECT_FLAG_COMPRESSED,
        CONNECT_FLAG_END_STREAM,
    };

    fn limits() -> ConnectLimits {
        ConnectLimits::new(256, 1024)
    }

    #[test]
    fn encodes_big_endian_header_and_decodes_round_trip() {
        let envelope = ConnectEnvelope::data(b"hello".to_vec());
        let encoded = ConnectEncoder::new(limits())
            .encode(&envelope)
            .expect("encode");
        assert_eq!(&encoded[..5], &[0, 0, 0, 0, 5]);
        assert_eq!(
            decode_connect_envelopes(&encoded, limits(), ConnectCompression::Identity)
                .expect("decode"),
            vec![envelope]
        );
    }

    #[test]
    fn accepts_fragmented_headers_and_payloads() {
        let encoded = ConnectEncoder::new(limits())
            .encode(&ConnectEnvelope::data(b"fragmented".to_vec()))
            .expect("encode");
        let mut decoder = ConnectDecoder::new(limits());
        let mut decoded = Vec::new();
        for byte in encoded {
            decoded.extend(decoder.feed(&[byte]).expect("feed"));
        }
        decoder.finish().expect("complete frame");
        assert_eq!(decoded, vec![ConnectEnvelope::data(b"fragmented".to_vec())]);
    }

    #[test]
    fn accepts_empty_envelopes_when_header_is_the_final_chunk() {
        let encoded = ConnectEncoder::new(limits())
            .encode(&ConnectEnvelope::data(Vec::new()))
            .expect("encode");
        let mut decoder = ConnectDecoder::new(limits());
        assert_eq!(
            decoder.feed(&encoded).expect("feed"),
            vec![ConnectEnvelope::data(Vec::new())]
        );
        decoder.finish().expect("complete frame");
    }

    #[test]
    fn gzip_round_trip_preserves_compressed_flag() {
        let envelope = ConnectEnvelope::compressed_data(vec![b'a'; 128]);
        let encoded = ConnectEncoder::with_gzip(limits())
            .encode(&envelope)
            .expect("encode");
        assert_eq!(encoded[0], CONNECT_FLAG_COMPRESSED);
        let decoded =
            decode_connect_envelopes(&encoded, limits(), ConnectCompression::Gzip).expect("decode");
        assert_eq!(decoded, vec![envelope]);
    }

    #[test]
    fn compressed_flag_requires_negotiated_gzip() {
        let encoded = ConnectEncoder::with_gzip(limits())
            .encode(&ConnectEnvelope::compressed_data(b"data".to_vec()))
            .expect("encode");
        assert_eq!(
            decode_connect_envelopes(&encoded, limits(), ConnectCompression::Identity),
            Err(ConnectError::CompressionNotNegotiated)
        );
    }

    #[test]
    fn rejects_reserved_and_compressed_end_stream_flags() {
        let mut decoder = ConnectDecoder::new(limits());
        assert_eq!(
            decoder.feed(&[0x80, 0, 0, 0, 0]),
            Err(ConnectError::InvalidFlags { flags: 0x80 })
        );
        let invalid = [
            CONNECT_FLAG_COMPRESSED | CONNECT_FLAG_END_STREAM,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(
            ConnectDecoder::new(limits()).feed(&invalid),
            Err(ConnectError::CompressedEndStream)
        );
    }

    #[test]
    fn rejects_wire_frames_above_limit_before_waiting_for_payload() {
        let input = [0, 0, 0, 0, 1, 0];
        assert_eq!(
            ConnectDecoder::new(ConnectLimits::new(0, 1)).feed(&input),
            Err(ConnectError::FrameTooLarge {
                observed: 1,
                limit: 0
            })
        );
    }

    #[test]
    fn rejects_decompression_bombs_after_output_limit() {
        let envelope = ConnectEnvelope::compressed_data(vec![b'x'; 128]);
        let encoded = ConnectEncoder::with_gzip(ConnectLimits::new(256, 128))
            .encode(&envelope)
            .expect("encode");
        assert_eq!(
            decode_connect_envelopes(
                &encoded,
                ConnectLimits::new(256, 32),
                ConnectCompression::Gzip,
            ),
            Err(ConnectError::DecompressedTooLarge {
                observed: 128,
                limit: 32
            })
        );
    }

    #[test]
    fn finish_rejects_truncated_header_and_payload() {
        let mut decoder = ConnectDecoder::new(limits());
        decoder.feed(&[0, 0]).expect("partial header");
        assert_eq!(decoder.finish(), Err(ConnectError::Truncated { bytes: 2 }));

        let mut decoder = ConnectDecoder::new(limits());
        decoder
            .feed(&[0, 0, 0, 0, 3, b'x'])
            .expect("partial payload");
        assert_eq!(decoder.finish(), Err(ConnectError::Truncated { bytes: 6 }));
    }

    #[test]
    fn end_stream_is_terminal() {
        let end = encode_connect_envelope(
            &ConnectEnvelope::end_stream(b"{}".to_vec()),
            limits(),
            ConnectCompression::Identity,
        )
        .expect("encode");
        let data = ConnectEncoder::new(limits())
            .encode(&ConnectEnvelope::data(b"late".to_vec()))
            .expect("encode");
        let mut combined = end;
        combined.extend(data);
        assert_eq!(
            decode_connect_envelopes(&combined, limits(), ConnectCompression::Identity),
            Err(ConnectError::AfterEndStream)
        );
    }

    #[test]
    fn invalid_gzip_is_reported() {
        let mut input = vec![CONNECT_FLAG_COMPRESSED, 0, 0, 0, 3];
        input.extend_from_slice(b"bad");
        assert!(matches!(
            decode_connect_envelopes(&input, limits(), ConnectCompression::Gzip),
            Err(ConnectError::InvalidGzip { .. })
        ));
    }

    #[test]
    fn trailing_gzip_bytes_are_not_another_payload_encoding() {
        let mut encoded = ConnectEncoder::with_gzip(limits())
            .encode(&ConnectEnvelope::compressed_data(b"data".to_vec()))
            .expect("encode");
        encoded[4] = encoded[4].checked_add(1).expect("short gzip payload");
        encoded.push(0xff);
        assert!(matches!(
            decode_connect_envelopes(&encoded, limits(), ConnectCompression::Gzip),
            Err(ConnectError::InvalidGzip { .. })
        ));
    }

    #[test]
    fn gzip_encoder_enforces_wire_frame_limit() {
        let error = ConnectEncoder::with_gzip(ConnectLimits::new(8, 1024))
            .encode(&ConnectEnvelope::compressed_data(vec![b'x'; 1024]))
            .expect_err("compressed payload exceeds frame limit");
        assert!(matches!(
            error,
            ConnectError::FrameTooLarge { observed, limit: 8 } if observed > 8
        ));
    }
}
