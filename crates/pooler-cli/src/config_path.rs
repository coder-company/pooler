//! Safe discovery of the one canonical Pooler configuration file.
//!
//! Discovery is intentionally small and deterministic. An explicitly supplied
//! path is always used as-is. Without one, a regular pooler.yaml entry (or any
//! other existing directory entry with that name) wins, and only then is a
//! platform configuration path selected. This module never selects an
//! alternate generated path or guesses at provider-specific filenames.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const CONFIG_DIRECTORY: &str = "pooler";
const CONFIG_FILENAME: &str = "pooler.yaml";

/// Resolve the configuration path for one CLI invocation.
pub(crate) fn resolve(explicit: Option<&Path>) -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("could not determine current directory")?;
    resolve_from(explicit, &current_dir, &PlatformEnvironment::from_process())
}

/// Resolve a configuration path against an explicit working directory and
/// platform environment.
///
/// Keeping the environment and working directory as inputs makes precedence
/// testable without changing process-global environment variables.
fn resolve_from(
    explicit: Option<&Path>,
    current_dir: &Path,
    environment: &PlatformEnvironment,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.as_os_str().is_empty() {
            bail!("configuration path must not be empty");
        }
        // An explicit path is never replaced by a fallback. ConfigLoader
        // performs the final regular-file and symlink safety check.
        if !directory_entry_exists(path)? {
            bail!(
                "failed to read configuration `{}`: file does not exist",
                path.display()
            );
        }
        return Ok(path.to_owned());
    }

    let working_directory_config = current_dir.join(CONFIG_FILENAME);
    if directory_entry_exists(&working_directory_config)? {
        return Ok(working_directory_config);
    }

    let platform = platform_config_path(environment)?;
    if directory_entry_exists(&platform)? {
        return Ok(platform);
    }
    bail!(
        "failed to read configuration `{}`: file does not exist (checked `{}` first)",
        platform.display(),
        working_directory_config.display()
    )
}

/// Return whether a path exists without following a final symlink.
///
/// `Path::exists` follows links and reports a broken link as absent.  That
/// would make a malicious or accidental `./pooler.yaml` link silently lose to
/// a different per-user configuration.  `symlink_metadata` preserves the
/// precedence decision; the config loader subsequently rejects the link.
fn directory_entry_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not inspect configuration candidate `{}`",
                path.display()
            )
        }),
    }
}

#[allow(clippy::needless_return)]
fn platform_config_path(environment: &PlatformEnvironment) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let root = if let Some(path) = environment.app_data.as_deref() {
            PathBuf::from(path)
        } else if let Some(path) = environment.user_profile.as_deref() {
            PathBuf::from(path).join("AppData\\Roaming")
        } else {
            bail!("could not determine the Windows configuration directory; set --config");
        };
        return config_path_under(&root);
    }

    #[cfg(target_os = "macos")]
    {
        let (name, root) = if let Some(path) = environment.xdg_config_home.as_deref() {
            ("XDG_CONFIG_HOME", PathBuf::from(path))
        } else if let Some(path) = environment.home.as_deref() {
            (
                "HOME",
                PathBuf::from(path).join("Library/Application Support"),
            )
        } else {
            bail!("could not determine HOME; set --config");
        };
        validate_directory(name, &root)?;
        return config_path_under(&root);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let (name, root) = if let Some(root) = environment.xdg_config_home.as_deref() {
            ("XDG_CONFIG_HOME", PathBuf::from(root))
        } else {
            let home = environment
                .home
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("could not determine HOME; set --config"))?;
            ("HOME", PathBuf::from(home).join(".config"))
        };
        validate_directory(name, &root)?;
        return config_path_under(&root);
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = environment;
        bail!("could not determine the platform configuration directory; set --config");
    }
}

fn config_path_under(root: &Path) -> Result<PathBuf> {
    if root.as_os_str().is_empty() {
        bail!("configuration directory must not be empty");
    }
    if !root.is_absolute() {
        bail!(
            "configuration directory `{}` must be absolute",
            root.display()
        );
    }
    Ok(root.join(CONFIG_DIRECTORY).join(CONFIG_FILENAME))
}

fn validate_directory(name: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("{name} must not be empty");
    }
    if !path.is_absolute() {
        bail!("{name} must be an absolute path");
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct PlatformEnvironment {
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
    #[cfg(target_os = "windows")]
    app_data: Option<OsString>,
    #[cfg(target_os = "windows")]
    user_profile: Option<OsString>,
}

impl PlatformEnvironment {
    fn from_process() -> Self {
        Self {
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            home: std::env::var_os("HOME"),
            #[cfg(target_os = "windows")]
            app_data: std::env::var_os("APPDATA"),
            #[cfg(target_os = "windows")]
            user_profile: std::env::var_os("USERPROFILE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(xdg: Option<&Path>, home: Option<&Path>) -> PlatformEnvironment {
        PlatformEnvironment {
            xdg_config_home: xdg.map(|path| path.as_os_str().to_owned()),
            home: home.map(|path| path.as_os_str().to_owned()),
            #[cfg(target_os = "windows")]
            app_data: None,
            #[cfg(target_os = "windows")]
            user_profile: None,
        }
    }

    #[test]
    fn explicit_missing_path_fails_without_falling_back() {
        let directory = tempfile::tempdir().expect("directory");
        let explicit = directory.path().join("operator.yaml");
        let local = directory.path().join(CONFIG_FILENAME);
        std::fs::write(&local, "version: 2\n").expect("local config");
        let platform_root = directory.path().join("xdg");
        std::fs::create_dir_all(platform_root.join(CONFIG_DIRECTORY)).expect("platform root");
        std::fs::write(
            platform_root.join(CONFIG_DIRECTORY).join(CONFIG_FILENAME),
            "version: 2\n",
        )
        .expect("platform config");

        let error = resolve_from(
            Some(&explicit),
            directory.path(),
            &environment(Some(&platform_root), None),
        )
        .expect_err("missing explicit path");
        assert!(error.to_string().contains(&explicit.display().to_string()));
    }

    #[test]
    fn existing_working_directory_config_precedes_platform_config() {
        let directory = tempfile::tempdir().expect("directory");
        let local = directory.path().join(CONFIG_FILENAME);
        std::fs::write(&local, "version: 2\n").expect("local config");
        let platform_root = directory.path().join("xdg");
        std::fs::create_dir_all(platform_root.join(CONFIG_DIRECTORY)).expect("platform root");
        let platform = platform_root.join(CONFIG_DIRECTORY).join(CONFIG_FILENAME);
        std::fs::write(&platform, "version: 2\n").expect("platform config");

        assert_eq!(
            resolve_from(
                None,
                directory.path(),
                &environment(Some(&platform_root), None),
            )
            .expect("discovered path"),
            local
        );
    }

    #[test]
    fn xdg_config_path_is_used_when_working_directory_is_empty() {
        let directory = tempfile::tempdir().expect("directory");
        let xdg = directory.path().join("xdg");
        let platform = xdg.join(CONFIG_DIRECTORY).join(CONFIG_FILENAME);
        std::fs::create_dir_all(platform.parent().expect("platform parent")).expect("directory");
        std::fs::write(&platform, "version: 2\n").expect("platform config");

        assert_eq!(
            resolve_from(None, directory.path(), &environment(Some(&xdg), None))
                .expect("discovered path"),
            platform
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn home_dot_config_path_is_used_without_xdg_config_home() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory.path().join("home");
        let platform = home
            .join(".config")
            .join(CONFIG_DIRECTORY)
            .join(CONFIG_FILENAME);
        std::fs::create_dir_all(platform.parent().expect("platform parent")).expect("directory");
        std::fs::write(&platform, "version: 2\n").expect("platform config");

        assert_eq!(
            resolve_from(None, directory.path(), &environment(None, Some(&home)))
                .expect("discovered path"),
            platform
        );
    }

    #[test]
    fn missing_platform_file_reports_the_canonical_filename() {
        let directory = tempfile::tempdir().expect("directory");
        let xdg = directory.path().join("xdg");
        let expected = xdg.join(CONFIG_DIRECTORY).join(CONFIG_FILENAME);
        let error = resolve_from(None, directory.path(), &environment(Some(&xdg), None))
            .expect_err("missing platform path");
        assert!(error.to_string().contains(&expected.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn a_working_directory_symlink_keeps_precedence_and_is_not_followed() {
        let directory = tempfile::tempdir().expect("directory");
        let target = directory.path().join("target.yaml");
        let local = directory.path().join(CONFIG_FILENAME);
        let platform_root = directory.path().join("xdg");
        std::fs::write(&target, "version: 2\n").expect("target");
        std::os::unix::fs::symlink(&target, &local).expect("symlink");
        std::fs::create_dir_all(platform_root.join(CONFIG_DIRECTORY)).expect("platform root");
        let platform = platform_root.join(CONFIG_DIRECTORY).join(CONFIG_FILENAME);
        std::fs::write(&platform, "version: 2\n").expect("platform config");

        let discovered = resolve_from(
            None,
            directory.path(),
            &environment(Some(&platform_root), None),
        )
        .expect("discovered path");
        assert_eq!(discovered, local);
        assert!(
            pooler_config::load_path(&discovered).is_err(),
            "the config loader must reject the symlink rather than following it"
        );
    }

    #[test]
    fn relative_platform_directories_are_rejected() {
        let directory = tempfile::tempdir().expect("directory");
        let relative = Path::new("relative-config");
        let error = resolve_from(None, directory.path(), &environment(Some(relative), None))
            .expect_err("relative XDG path");
        assert!(error.to_string().contains("XDG_CONFIG_HOME"));
        assert!(error.to_string().contains("absolute"));
    }
}
