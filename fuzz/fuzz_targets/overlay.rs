#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "overlay_harness.rs"]
mod overlay_harness;

fuzz_target!(|input: &[u8]| {
    let _ = overlay_harness::execute(input);
});
