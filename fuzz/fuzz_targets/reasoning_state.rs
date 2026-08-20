#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_protocol::{LossPolicy, OpenAiChatEventDecoder, OpenAiChatEventEncoder, StreamEvent};

const MAX_INPUT_BYTES: usize = 128 * 1024;

fn encode_events(encoder: &mut OpenAiChatEventEncoder, events: &[StreamEvent]) {
    for event in events {
        let _ = encoder.encode_event(event, LossPolicy::Degrade);
    }
}

// Feed a sequence of OpenAI Chat chunks through the stateful decoder and
// encoder. Newlines delimit chunks in the committed seed corpus; arbitrary
// mutations can still reach malformed JSON and lifecycle error paths.
fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    let mut decoder = OpenAiChatEventDecoder::new();
    let mut encoder = OpenAiChatEventEncoder::new();

    for chunk in input.split(|byte| *byte == b'\n') {
        if chunk.is_empty() {
            continue;
        }
        let events = if chunk == b"[DONE]" {
            decoder.decode_data(chunk)
        } else {
            decoder.decode_chunk(chunk)
        };
        let Ok(events) = events else {
            return;
        };
        encode_events(&mut encoder, &events);
    }

    // A missing sentinel is an ordinary incomplete-stream input. Calling the
    // production finish path makes that state observable without inventing a
    // terminal event in the harness.
    if let Ok(events) = decoder.decode_data(b"[DONE]") {
        encode_events(&mut encoder, &events);
    }
});
