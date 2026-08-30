use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const CONFIG: &str = r#"version: 2
listeners:
  local:
    bind: 127.0.0.1:0
upstreams:
  upstream:
    url: http://127.0.0.1:1
routes:
  - id: test-route
    listen: local
    match:
      methods: [POST]
      path: /v1/test
    ingress:
      mode: opaque
    target:
      provider: upstream
"#;

fn invoke(config: &Path, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pooler"));
    command
        .arg("--config")
        .arg(config)
        .arg("endpoint-inventory");
    if json {
        command.arg("--json");
    }
    command.output().expect("pooler process")
}

#[test]
fn endpoint_inventory_json_alias_preserves_identical_machine_output() {
    let directory = tempfile::tempdir().expect("temporary config directory");
    let config = directory.path().join("pooler.yaml");
    fs::write(&config, CONFIG).expect("configuration fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
            .expect("private configuration permissions");
    }

    let default = invoke(&config, false);
    let explicit = invoke(&config, true);
    assert!(
        default.status.success(),
        "default endpoint inventory failed: {}",
        String::from_utf8_lossy(&default.stderr)
    );
    assert!(
        explicit.status.success(),
        "--json endpoint inventory failed: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    assert!(default.stderr.is_empty(), "unexpected stderr: {default:?}");
    assert!(
        explicit.stderr.is_empty(),
        "unexpected stderr: {explicit:?}"
    );
    assert_eq!(default.stdout, explicit.stdout);

    let value: Value = serde_json::from_slice(&default.stdout).expect("inventory JSON");
    assert_eq!(value["listeners"][0]["id"], "local");
    assert_eq!(value["listeners"][0]["routes"][0]["id"], "test-route");
}
