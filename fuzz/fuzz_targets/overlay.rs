#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_yml::Value;

fuzz_target!(|input: &[u8]| {
    let Ok(value) = serde_yml::from_slice::<Value>(input) else {
        return;
    };
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    let _ = mapping.get(Value::String("imports".to_owned()));
    let _ = mapping.get(Value::String("merge".to_owned()));
    let _ = mapping.get(Value::String("remove".to_owned()));
});
