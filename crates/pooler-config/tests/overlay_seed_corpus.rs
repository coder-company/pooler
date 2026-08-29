use std::fs;
use std::path::Path;

use pooler_config::ConfigLoader;
use tempfile::tempdir;

fn write_owner_private_config(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[test]
fn committed_overlay_seeds_replay_named_merge_and_remove() {
    let directory = tempdir().expect("temporary fixture directory");
    let base = directory.path().join("base.yaml");
    let merge = directory.path().join("named-map-merge.yaml");
    let remove = directory.path().join("named-list-remove.yaml");
    let root = directory.path().join("root.yaml");
    write_owner_private_config(
        &base,
        "version: 2\nupstreams:\n  local:\n    url: http://127.0.0.1:9000\nroutes:\n  - id: obsolete\n    listen: local\n    match:\n      path: /obsolete\n    target:\n      provider: local\n",
    )
    .expect("base fixture");
    write_owner_private_config(
        &merge,
        include_str!("../../../fuzz/corpus/overlay/named-map-merge.yaml"),
    )
    .expect("merge seed");
    write_owner_private_config(
        &remove,
        include_str!("../../../fuzz/corpus/overlay/named-list-remove.yaml"),
    )
    .expect("remove seed");
    write_owner_private_config(
        &root,
        "version: 2\nimports:\n  - file: base.yaml\n  - overlay: named-map-merge.yaml\n  - overlay: named-list-remove.yaml\n",
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

#[test]
fn semantic_overlay_seed_replays_merge_render_and_compile() {
    let directory = tempdir().expect("temporary fixture directory");
    let base = directory.path().join("base.yaml");
    let overlay = directory.path().join("semantic-route-merge.yaml");
    let root = directory.path().join("root.yaml");
    write_owner_private_config(
        &base,
        "version: 2\nlisteners:\n  local:\n    bind: 127.0.0.1:0\nupstreams:\n  local:\n    url: http://127.0.0.1:1\nroutes:\n  - id: obsolete\n    listen: local\n    match:\n      path: /obsolete\n    target: local\n",
    )
    .expect("base fixture");
    write_owner_private_config(
        &overlay,
        include_str!("../../../fuzz/corpus/overlay/semantic-route-merge.yaml"),
    )
    .expect("semantic overlay seed");
    write_owner_private_config(
        &root,
        "version: 2\nimports:\n  - file: base.yaml\n  - overlay: semantic-route-merge.yaml\n",
    )
    .expect("root fixture");

    let loaded = ConfigLoader::default()
        .load(&root)
        .expect("semantic overlay should load");
    let rendered = ConfigLoader::default()
        .render(&root)
        .expect("semantic overlay should render");
    let compiled = loaded.compile().expect("semantic overlay should compile");

    assert!(rendered.contains("http://127.0.0.1:2"));
    assert!(!rendered.contains("merge:"));
    assert!(!rendered.contains("remove:"));
    assert!(compiled.route("obsolete").is_none());
    assert!(compiled.route("replacement").is_some());
}
