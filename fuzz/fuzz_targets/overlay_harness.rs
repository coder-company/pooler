use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use pooler_config::ConfigLoader;

const MAX_INPUT_BYTES: usize = 128 * 1024;

const BASE_YAML: &str = r#"version: 2
listeners:
  local:
    bind: 127.0.0.1:0
upstreams:
  local:
    url: http://127.0.0.1:1
routes:
  - id: obsolete
    listen: local
    match:
      path: /obsolete
    target: local
"#;

const ROOT_YAML: &str = r#"version: 2
imports:
  - file: base.yaml
  - overlay: overlay.yaml
"#;

static NEXT_WORKDIR: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Execution {
    pub rendered: bool,
    pub loaded: bool,
    pub compiled: bool,
}

pub fn execute(input: &[u8]) -> Execution {
    let Some(directory) = workdir() else {
        return Execution::default();
    };
    let base = directory.join("base.yaml");
    let root = directory.join("root.yaml");
    let overlay = directory.join("overlay.yaml");
    let input = &input[..input.len().min(MAX_INPUT_BYTES)];

    if write_owner_private_config(&base, BASE_YAML).is_err()
        || write_owner_private_config(&root, ROOT_YAML).is_err()
        || write_owner_private_config(&overlay, input).is_err()
    {
        cleanup(&directory);
        return Execution::default();
    }

    let loader = ConfigLoader::new(4);
    // Keep render, load, and compile in the target so every fuzz iteration
    // reaches the production import, merge, and validation paths when the
    // generated overlay is valid. Invalid inputs are expected to return an
    // error from one of these bounded stages.
    let rendered = loader.render(&root).is_ok();
    let config = loader.load(&root);
    let loaded = config.is_ok();
    let compiled = config.is_ok_and(|config| config.compile().is_ok());
    cleanup(&directory);

    Execution {
        rendered,
        loaded,
        compiled,
    }
}

fn write_owner_private_config(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn workdir() -> Option<PathBuf> {
    for _ in 0..8 {
        let sequence = NEXT_WORKDIR.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "pooler-fuzz-overlay-{}-{sequence}",
            std::process::id()
        ));
        match std::fs::create_dir(&directory) {
            Ok(()) => return Some(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

fn cleanup(directory: &Path) {
    let _ = std::fs::remove_dir_all(directory);
}
