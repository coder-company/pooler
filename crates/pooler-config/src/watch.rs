//! Deterministic, dependency-aware configuration polling.
//!
//! The watcher intentionally uses a small polling loop instead of a platform
//! notification dependency. Configuration files are tiny and polling gives
//! identical behavior on Linux, macOS, and Windows, including editors that
//! replace a file by rename. The caller chooses the async scheduling policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_yml::Value;

use crate::{ConfigError, ConfigLoader, LoadedConfig};

/// Default quiet period used to coalesce an editor's write burst.
pub const DEFAULT_RELOAD_DEBOUNCE: Duration = Duration::from_millis(50);

/// Default polling interval for a running process.
pub const DEFAULT_RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A parsed candidate discovered by [`ConfigWatcher`].
#[derive(Clone, Debug)]
pub struct ConfigCandidate {
    loaded: LoadedConfig,
}

impl ConfigCandidate {
    /// Parsed candidate source.
    #[must_use]
    pub const fn loaded(&self) -> &LoadedConfig {
        &self.loaded
    }

    /// Compile the candidate with a caller-owned generation.
    pub fn compile_with_generation(
        &self,
        generation: u64,
    ) -> Result<crate::CompiledConfig, ConfigError> {
        self.loaded.compile_with_generation(generation)
    }

    /// Whether the expanded source differs from the active source.
    #[must_use]
    pub fn is_noop_against(&self, active: &LoadedConfig) -> bool {
        self.loaded.rendered() == active.rendered()
    }
}

/// A dependency-aware configuration watcher.
///
/// `poll` is non-blocking. It reports a candidate only after all currently
/// tracked files have been quiet for the configured debounce period. A caller
/// must call [`Self::accept`] after a candidate has been successfully applied;
/// rejected candidates leave the active source untouched; unresolved import
/// paths discovered during a failed load remain watched for later creation.
#[derive(Debug)]
pub struct ConfigWatcher {
    loader: ConfigLoader,
    active: LoadedConfig,
    debounce: Duration,
    observed: BTreeMap<PathBuf, FileStamp>,
    unresolved: BTreeSet<PathBuf>,
    pending_since: Option<Instant>,
    attempted: Option<BTreeMap<PathBuf, FileStamp>>,
}

impl ConfigWatcher {
    /// Load a root file and begin watching it and all imported files.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::with_loader(ConfigLoader::default(), path)
    }

    /// Load a root file with a caller-provided resolver.
    pub fn with_loader(loader: ConfigLoader, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::with_loader_and_debounce(loader, path, DEFAULT_RELOAD_DEBOUNCE)
    }

    /// Load a root file with an explicit debounce period.
    pub fn with_loader_and_debounce(
        loader: ConfigLoader,
        path: impl AsRef<Path>,
        debounce: Duration,
    ) -> Result<Self, ConfigError> {
        let active = loader.load_tracked(path)?;
        let observed = file_stamps(active.dependencies());
        Ok(Self {
            loader,
            active,
            debounce,
            observed,
            unresolved: BTreeSet::new(),
            pending_since: None,
            attempted: None,
        })
    }

    /// Active parsed source.
    #[must_use]
    pub const fn active(&self) -> &LoadedConfig {
        &self.active
    }

    /// Canonical root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.active.root()
    }

    /// Current dependency set, including the root file.
    #[must_use]
    pub fn dependencies(&self) -> &[PathBuf] {
        self.active.dependencies()
    }

    /// Poll for a debounced candidate without blocking the caller.
    pub fn poll(&mut self) -> Result<Option<ConfigCandidate>, ConfigError> {
        let current = file_stamps(&self.watched_paths());
        if current != self.observed {
            self.observed = current;
            self.pending_since = Some(Instant::now());
            self.attempted = None;
            return Ok(None);
        }

        let Some(pending_since) = self.pending_since else {
            return Ok(None);
        };
        if pending_since.elapsed() < self.debounce {
            return Ok(None);
        }
        if self.attempted.as_ref() == Some(&self.observed) {
            return Ok(None);
        }

        self.attempted = Some(self.observed.clone());
        let candidate = match self.loader.load_tracked(self.active.root()) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.refresh_unresolved_paths();
                self.observed = file_stamps(&self.watched_paths());
                self.attempted = Some(self.observed.clone());
                return Err(error);
            }
        };
        self.unresolved = candidate
            .dependencies()
            .iter()
            .filter(|path| !self.active.dependencies().contains(path))
            .cloned()
            .collect();
        self.observed = file_stamps(&self.watched_paths());
        self.pending_since = None;
        Ok(Some(ConfigCandidate { loaded: candidate }))
    }

    /// Load a candidate immediately, bypassing polling and debounce.
    ///
    /// This is the manual/SIGHUP path. The active source is not changed until
    /// the caller successfully applies the returned candidate and calls
    /// [`Self::accept`].
    pub fn force_candidate(&mut self) -> Result<ConfigCandidate, ConfigError> {
        let loaded = match self.loader.load_tracked(self.active.root()) {
            Ok(loaded) => loaded,
            Err(error) => {
                self.refresh_unresolved_paths();
                self.observed = file_stamps(&self.watched_paths());
                return Err(error);
            }
        };
        self.unresolved = loaded
            .dependencies()
            .iter()
            .filter(|path| !self.active.dependencies().contains(path))
            .cloned()
            .collect();
        self.observed = file_stamps(&self.watched_paths());
        Ok(ConfigCandidate { loaded })
    }

    /// Mark a candidate as successfully applied and switch the dependency set.
    pub fn accept(&mut self, candidate: ConfigCandidate) {
        self.active = candidate.loaded;
        self.unresolved.clear();
        self.observed = file_stamps(&self.watched_paths());
        self.pending_since = None;
        self.attempted = None;
    }

    fn watched_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.active.dependencies().to_vec();
        paths.extend(self.unresolved.iter().cloned());
        paths.sort();
        paths.dedup();
        paths
    }

    fn refresh_unresolved_paths(&mut self) {
        let mut paths = BTreeSet::new();
        collect_import_paths(self.active.root(), &mut paths, &mut BTreeSet::new());
        self.unresolved = paths
            .into_iter()
            .filter(|path| !self.active.dependencies().contains(path))
            .collect();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    exists: bool,
    length: u64,
    digest: u64,
}

fn file_stamps(paths: &[PathBuf]) -> BTreeMap<PathBuf, FileStamp> {
    paths
        .iter()
        .map(|path| (path.clone(), file_stamp(path)))
        .collect()
}

fn file_stamp(path: &Path) -> FileStamp {
    let Ok(bytes) = fs::read(path) else {
        return FileStamp {
            exists: false,
            length: 0,
            digest: 0,
        };
    };
    FileStamp {
        exists: true,
        length: bytes.len() as u64,
        digest: fnv1a(&bytes),
    }
}

fn collect_import_paths(path: &Path, paths: &mut BTreeSet<PathBuf>, stack: &mut BTreeSet<PathBuf>) {
    let identity = canonical_or_path(path);
    if !stack.insert(identity.clone()) {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        stack.remove(&identity);
        return;
    };
    let Ok(document) = serde_yml::from_str::<Value>(&text) else {
        stack.remove(&identity);
        return;
    };
    let Some(imports) = document
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String("imports".to_owned())))
        .and_then(Value::as_sequence)
    else {
        stack.remove(&identity);
        return;
    };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for import in imports {
        let Some(mapping) = import.as_mapping() else {
            continue;
        };
        for key in ["file", "overlay"] {
            let Some(relative) = mapping
                .get(Value::String(key.to_owned()))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let imported = canonical_or_path(&parent.join(relative));
            paths.insert(imported.clone());
            collect_import_paths(&imported, paths, stack);
        }
    }
    stack.remove(&identity);
}

fn canonical_or_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread::sleep;

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "pooler-config-watch-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("test directory");
            Self(path)
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, text).expect("test config");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tracks_imports_and_debounces_then_accepts() {
        let dir = TestDir::new();
        let base = dir.write(
            "base.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\n",
        );
        let root = dir.write("root.yaml", "imports: [{file: base.yaml}]\nversion: 1\n");
        let mut watcher = ConfigWatcher::with_loader_and_debounce(
            ConfigLoader::default(),
            &root,
            Duration::from_millis(2),
        )
        .expect("watcher loads");
        assert!(watcher
            .dependencies()
            .contains(&fs::canonicalize(&base).unwrap()));

        fs::write(
            &base,
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:2}}\n",
        )
        .expect("rewrite import");
        assert!(watcher.poll().expect("first poll").is_none());
        sleep(Duration::from_millis(4));
        let candidate = watcher.poll().expect("debounced poll").expect("candidate");
        assert!(!candidate.is_noop_against(watcher.active()));
        watcher.accept(candidate);
        assert_eq!(
            watcher.active().config().listeners["local"].bind,
            "127.0.0.1:2"
        );
    }

    #[test]
    fn invalid_candidate_does_not_replace_active_source() {
        let dir = TestDir::new();
        let root = dir.write(
            "root.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\n",
        );
        let mut watcher =
            ConfigWatcher::with_loader_and_debounce(ConfigLoader::default(), &root, Duration::ZERO)
                .expect("watcher loads");
        fs::write(&root, "version: [bad]\n").expect("invalid rewrite");
        assert!(watcher.poll().expect("initial poll").is_none());
        let error = watcher.poll().expect_err("invalid candidate");
        assert!(error.to_string().contains("version"));
        assert_eq!(
            watcher.active().config().listeners["local"].bind,
            "127.0.0.1:1"
        );
    }

    #[test]
    fn debounce_reload_candidate_is_ready_within_two_hundred_fifty_ms() {
        let dir = TestDir::new();
        let root = dir.write(
            "root.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\n",
        );
        let mut watcher = ConfigWatcher::new(&root).expect("watcher loads");
        fs::write(
            &root,
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:2}}\n",
        )
        .expect("rewrite root");
        let started = Instant::now();
        loop {
            if let Some(candidate) = watcher.poll().expect("poll succeeds") {
                assert!(!candidate.is_noop_against(watcher.active()));
                assert!(started.elapsed() < Duration::from_millis(250));
                break;
            }
            assert!(started.elapsed() < Duration::from_millis(250));
            sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn failed_import_is_retried_when_the_missing_dependency_is_created() {
        let dir = TestDir::new();
        let root = dir.write(
            "root.yaml",
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:1}}\n",
        );
        let missing = dir.0.join("later.yaml");
        let mut watcher =
            ConfigWatcher::with_loader_and_debounce(ConfigLoader::default(), &root, Duration::ZERO)
                .expect("watcher loads");
        fs::write(&root, "imports: [{file: later.yaml}]\nversion: 1\n")
            .expect("add missing import");
        assert!(watcher.poll().expect("root change poll").is_none());
        assert!(watcher
            .poll()
            .expect_err("missing import is rejected")
            .to_string()
            .contains("later.yaml"));
        assert!(watcher.poll().expect("same failure is quiet").is_none());

        fs::write(
            &missing,
            "version: 1\nlisteners: {local: {bind: 127.0.0.1:2}}\n",
        )
        .expect("create missing import");
        assert!(watcher.poll().expect("new dependency poll").is_none());
        let candidate = watcher
            .poll()
            .expect("candidate poll")
            .expect("created import candidate");
        assert_eq!(
            candidate.loaded().config().listeners["local"].bind,
            "127.0.0.1:2"
        );
        watcher.accept(candidate);
    }
}
