#![no_main]

use libfuzzer_sys::fuzz_target;
use pooler_config::{compile_yaml, RouteRequest};

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TEMPLATE_SEGMENTS: usize = 32;

fn hex_digit(value: u8) -> u8 {
    match value & 0x0f {
        0..=9 => b'0' + (value & 0x0f),
        value => b'a' + (value - 10),
    }
}

/// Turn arbitrary bytes into a valid path template and a matching request.
/// Every byte still changes the route shape: odd bytes create a parameter
/// segment and even bytes create a literal segment.
fn generated_template(input: &[u8]) -> (String, String) {
    let mut template = String::from("/");
    let mut request = String::from("/");
    for (index, chunk) in input.chunks(2).take(MAX_TEMPLATE_SEGMENTS).enumerate() {
        if index != 0 {
            template.push('/');
            request.push('/');
        }
        if chunk.first().is_some_and(|value| value & 1 == 1) {
            template.push_str("{segment");
            template.push_str(&index.to_string());
            template.push('}');
            request.push_str("value");
        } else {
            for byte in chunk {
                template.push(hex_digit(*byte >> 4) as char);
                template.push(hex_digit(*byte) as char);
            }
            if chunk.is_empty() {
                template.push('0');
                request.push('0');
            } else {
                for byte in chunk {
                    request.push(hex_digit(byte >> 4) as char);
                    request.push(hex_digit(*byte) as char);
                }
            }
        }
    }
    (template, request)
}

fn config_for(template: &str) -> String {
    let quoted = serde_json::to_string(template).expect("template string is serializable");
    format!(
        "version: 1\nlisteners:\n  fuzz:\n    bind: 127.0.0.1:0\nupstreams:\n  fuzz:\n    url: http://127.0.0.1:1\nroutes:\n  - id: fuzz-template\n    listen: fuzz\n    match:\n      method: POST\n      path_template: {quoted}\n    target: fuzz\n"
    )
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];
    let (template, request_path) = generated_template(input);
    let config_text = config_for(&template);
    let Ok(config) = compile_yaml("fuzz-route.yaml", &config_text) else {
        return;
    };

    let request = RouteRequest::new(
        "fuzz",
        "POST".parse().expect("POST is a valid HTTP method"),
        format!("{request_path}?fuzz=1"),
    );
    let _ = config.match_route_request(&request);
    let _ = config.match_route_request(&RouteRequest::new(
        "fuzz",
        "POST".parse().expect("POST is a valid HTTP method"),
        "/does-not-match",
    ));

    // Compile the raw, escaped input as well. This covers rejection paths for
    // malformed, query-bearing, and otherwise invalid template declarations.
    let raw = String::from_utf8_lossy(input);
    let _ = compile_yaml("fuzz-route-raw.yaml", &config_for(raw.as_ref()));
});
