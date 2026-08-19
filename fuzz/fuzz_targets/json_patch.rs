#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_protocol::{JsonPatchLimits, PreservedJson};
use serde_json::json;

fuzz_target!(|input: &[u8]| {
    let mut document = match PreservedJson::from_bytes(input.to_vec()) {
        Ok(document) => document,
        Err(_) => return,
    };
    let pointer = match input.first().copied().unwrap_or_default() % 3 {
        0 => "/model",
        1 => "/messages/0/content",
        _ => "/items/0",
    };
    let _ = document.set_pointer_bounded(
        pointer,
        json!({"fuzzed": input.len()}),
        JsonPatchLimits::new(256, 32, 4096),
    );
    let _ = document.extract_model();
});
