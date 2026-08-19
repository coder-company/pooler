#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_http::{SseLimits, SseParser};

fuzz_target!(|input: &[u8]| {
    let mut parser = SseParser::with_limits(SseLimits::new(16 * 1024, 256 * 1024));
    for chunk in input.chunks(7) {
        if parser.feed(chunk).is_err() {
            return;
        }
    }
    let _ = parser.finish();
});
