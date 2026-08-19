use pooler_protocol::{JsonPatchLimits, PreservedJson};
use serde_json::json;

#[test]
fn committed_json_seeds_preserve_models_and_unknown_values() {
    let seeds = [
        include_bytes!("../../../fuzz/corpus/json/model-and-unknown.json").as_slice(),
        include_bytes!("../../../fuzz/corpus/json/pointer-escapes.json").as_slice(),
        include_bytes!("../../../fuzz/corpus/json/array-and-null.json").as_slice(),
    ];

    for seed in seeds {
        let document = PreservedJson::from_bytes(seed.to_vec()).expect("valid JSON seed");
        assert_eq!(
            document.extract_model().expect("model inspection"),
            Some("gpt-seed")
        );
    }

    let document = PreservedJson::from_bytes(
        include_bytes!("../../../fuzz/corpus/json/model-and-unknown.json").to_vec(),
    )
    .expect("valid unknown-field seed");
    assert_eq!(document.pointer("/unknown/nested"), Some(&json!(true)));
    assert_eq!(
        document.original_bytes(),
        include_bytes!("../../../fuzz/corpus/json/model-and-unknown.json")
    );
}

#[test]
fn pointer_escape_seed_replays_bounded_mutations() {
    let mut document = PreservedJson::from_bytes(
        include_bytes!("../../../fuzz/corpus/json/pointer-escapes.json").to_vec(),
    )
    .expect("valid pointer seed");
    let limits = JsonPatchLimits::default();

    document
        .set_pointer_bounded("/metadata/a~1b", json!("updated-slash"), limits)
        .expect("escaped slash pointer");
    document
        .set_pointer_bounded("/metadata/a~0b", json!("updated-tilde"), limits)
        .expect("escaped tilde pointer");
    document
        .set_pointer_bounded("/items/1", json!("updated-item"), limits)
        .expect("array pointer");

    assert_eq!(
        document.pointer("/metadata/a~1b"),
        Some(&json!("updated-slash"))
    );
    assert_eq!(
        document.pointer("/metadata/a~0b"),
        Some(&json!("updated-tilde"))
    );
    assert_eq!(document.pointer("/items/1"), Some(&json!("updated-item")));
}
