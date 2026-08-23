use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const VALID_CONFIG: &str = "version: 2\n";
const INVALID_VERSION: &str = "version: 999\n";

fn invoke(cwd: &Path, args: &[&str], xdg: &Path, home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pooler"))
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg)
        .args(args)
        .output()
        .expect("pooler process")
}

#[test]
fn working_directory_config_precedes_platform_config() {
    let directory = tempfile::tempdir().expect("directory");
    let xdg = directory.path().join("xdg");
    let platform = xdg.join("pooler/pooler.yaml");
    fs::create_dir_all(platform.parent().expect("platform parent")).expect("platform directory");
    fs::write(&platform, VALID_CONFIG).expect("platform config");
    let local = directory.path().join("pooler.yaml");
    fs::write(&local, INVALID_VERSION).expect("working-directory config");

    let output = invoke(directory.path(), &["check"], &xdg, directory.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(stderr.contains(&local.display().to_string()), "{stderr}");
    assert!(
        !stderr.contains(&platform.display().to_string()),
        "{stderr}"
    );
}

#[test]
fn platform_config_is_used_when_working_directory_config_is_absent() {
    let directory = tempfile::tempdir().expect("directory");
    let xdg = directory.path().join("xdg");
    let platform = xdg.join("pooler/pooler.yaml");
    fs::create_dir_all(platform.parent().expect("platform parent")).expect("platform directory");
    fs::write(&platform, VALID_CONFIG).expect("platform config");

    let output = invoke(directory.path(), &["check"], &xdg, directory.path());
    assert!(
        output.status.success(),
        "platform configuration was not discovered: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "configuration is valid\n"
    );
}

#[test]
fn explicit_config_is_exact_and_does_not_fall_back() {
    let directory = tempfile::tempdir().expect("directory");
    let xdg = directory.path().join("xdg");
    let platform = xdg.join("pooler/pooler.yaml");
    fs::create_dir_all(platform.parent().expect("platform parent")).expect("platform directory");
    fs::write(&platform, VALID_CONFIG).expect("platform config");
    fs::write(directory.path().join("pooler.yaml"), VALID_CONFIG).expect("local config");
    let explicit = directory.path().join("operator.yaml");
    fs::write(&explicit, INVALID_VERSION).expect("explicit config");

    let output = invoke(
        directory.path(),
        &["--config", explicit.to_str().expect("UTF-8 path"), "check"],
        &xdg,
        directory.path(),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(stderr.contains(&explicit.display().to_string()), "{stderr}");
}

#[test]
fn missing_default_reports_canonical_path_and_does_not_guess_provider_files() {
    let directory = tempfile::tempdir().expect("directory");
    let xdg = directory.path().join("xdg");
    let provider_named = xdg.join("pooler/openai-device.yaml");
    fs::create_dir_all(provider_named.parent().expect("platform parent"))
        .expect("platform directory");
    fs::write(&provider_named, VALID_CONFIG).expect("provider-named config");
    let expected = xdg.join("pooler/pooler.yaml");

    let output = invoke(directory.path(), &["check"], &xdg, directory.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(stderr.contains("failed to read configuration"), "{stderr}");
    assert!(stderr.contains(&expected.display().to_string()), "{stderr}");
    assert!(stderr.contains("file does not exist"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn working_directory_symlink_is_not_followed_or_replaced() {
    let directory = tempfile::tempdir().expect("directory");
    let xdg = directory.path().join("xdg");
    let platform = xdg.join("pooler/pooler.yaml");
    fs::create_dir_all(platform.parent().expect("platform parent")).expect("platform directory");
    fs::write(&platform, VALID_CONFIG).expect("platform config");
    let target = directory.path().join("target.yaml");
    fs::write(&target, VALID_CONFIG).expect("target config");
    let local = directory.path().join("pooler.yaml");
    std::os::unix::fs::symlink(&target, &local).expect("working-directory symlink");

    let output = invoke(directory.path(), &["check"], &xdg, directory.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "symlink was unexpectedly accepted: {output:?}"
    );
    assert!(stderr.contains("regular file"), "{stderr}");
    assert!(
        !stderr.contains(&platform.display().to_string()),
        "{stderr}"
    );
}
