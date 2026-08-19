use std::fs;

use pooler_config::ConfigLoader;
use tempfile::tempdir;

#[test]
fn committed_overlay_seeds_replay_named_merge_and_remove() {
    let directory = tempdir().expect("temporary fixture directory");
    let base = directory.path().join("base.yaml");
    let merge = directory.path().join("named-map-merge.yaml");
    let remove = directory.path().join("named-list-remove.yaml");
    let root = directory.path().join("root.yaml");
    fs::write(
        &base,
        "version: 1\nupstreams:\n  local:\n    url: http://127.0.0.1:9000\nroutes:\n  - id: obsolete\n    listen: local\n    match:\n      path: /obsolete\n    target:\n      provider: local\n",
    )
    .expect("base fixture");
    fs::write(
        &merge,
        include_str!("../../../fuzz/corpus/overlay/named-map-merge.yaml"),
    )
    .expect("merge seed");
    fs::write(
        &remove,
        include_str!("../../../fuzz/corpus/overlay/named-list-remove.yaml"),
    )
    .expect("remove seed");
    fs::write(
        &root,
        "version: 1\nimports:\n  - file: base.yaml\n  - overlay: named-map-merge.yaml\n  - overlay: named-list-remove.yaml\n",
    )
    .expect("root fixture");

    let rendered = ConfigLoader::default()
        .render(&root)
        .expect("overlay seeds should replay");

    assert!(rendered.contains("http://127.0.0.1:9001"));
    assert!(!rendered.contains("id: obsolete"));
    assert!(!rendered.contains("merge:"));
    assert!(!rendered.contains("remove:"));
}

#[test]
fn conflict_seed_is_valid_yaml_and_keeps_both_import_declarations() {
    let seed = include_str!("../../../fuzz/corpus/overlay/conflict.yaml");
    let value: serde_yml::Value = serde_yml::from_str(seed).expect("valid overlay seed");
    let imports = value
        .get("imports")
        .and_then(serde_yml::Value::as_sequence)
        .expect("conflict seed imports");

    assert_eq!(imports.len(), 2);
}
