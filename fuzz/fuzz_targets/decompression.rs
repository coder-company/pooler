#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_protocol::{decode_gzip_payload, ConnectDecoder, ConnectLimits};

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024;

fn decode_hex_seed(input: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(input).ok()?;
    let mut bytes = Vec::new();
    for token in text.split_whitespace() {
        if token.len() != 2 {
            return None;
        }
        bytes.push(u8::from_str_radix(token, 16).ok()?);
    }
    Some(bytes)
}

// Exercise both the standalone gzip boundary and the framed Connect path.
//
// The input is capped before either decoder sees it.  The production decoders
// enforce the output and frame bounds independently, so a compression-ratio
// bomb cannot make this harness retain unbounded data.
fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    let input = decode_hex_seed(input).unwrap_or_else(|| input.to_vec());
    let limits = ConnectLimits::new(MAX_FRAME_BYTES, MAX_DECOMPRESSED_BYTES);

    let _ = decode_gzip_payload(&input, limits.max_decompressed_bytes);

    let mut decoder = ConnectDecoder::with_gzip(limits);
    for chunk in input.chunks(11) {
        if decoder.feed(chunk).is_err() {
            break;
        }
    }
    let _ = decoder.finish();
});
