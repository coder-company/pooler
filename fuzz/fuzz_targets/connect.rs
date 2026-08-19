#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_protocol::{ConnectDecoder, ConnectLimits};

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

fuzz_target!(|input: &[u8]| {
    let input = decode_hex_seed(input).unwrap_or_else(|| input.to_vec());
    let mut decoder = ConnectDecoder::new(ConnectLimits::new(256 * 1024, 512 * 1024));
    for chunk in input.chunks(5) {
        if decoder.feed(chunk).is_err() {
            return;
        }
    }
    let _ = decoder.finish();
});
