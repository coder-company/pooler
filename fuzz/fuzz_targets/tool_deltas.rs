#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_protocol::OpenAiChatEventDecoder;

fuzz_target!(|input: &[u8]| {
    let mut decoder = OpenAiChatEventDecoder::new();
    let _ = decoder.decode_chunk(input);
    let _ = decoder.decode_data(b"[DONE]");
});
