use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn invoke(config: &Path, command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pooler"))
        .arg("--config")
        .arg(config)
        .arg(command)
        .output()
        .expect("pooler process")
}

fn write_config(directory: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("configuration fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private configuration permissions");
    }
    path
}

#[test]
fn check_rejects_concrete_bind_collisions_and_allows_ephemeral_binds() {
    let directory = tempfile::tempdir().expect("temporary config directory");
    let fixed = write_config(
        directory.path(),
        "fixed.yaml",
        "version: 2\nlisteners: {one: {bind: 127.0.0.1:18470}, two: {bind: 127.0.0.1:18470}}\n",
    );
    let fixed_output = invoke(&fixed, "check");
    assert!(
        !fixed_output.status.success(),
        "fixed duplicate unexpectedly passed: {fixed_output:?}"
    );
    assert!(
        fixed_output.stdout.is_empty(),
        "unexpected stdout: {fixed_output:?}"
    );
    let fixed_error = String::from_utf8_lossy(&fixed_output.stderr);
    assert!(
        fixed_error.contains("listener bind `127.0.0.1:18470`"),
        "{fixed_error}"
    );
    assert!(fixed_error.contains("listeners.one"), "{fixed_error}");
    assert!(fixed_error.contains("listeners.two"), "{fixed_error}");

    let wildcard = write_config(
        directory.path(),
        "wildcard.yaml",
        "version: 2\nlisteners: {wildcard: {bind: 0.0.0.0:18472}, specific: {bind: 127.0.0.1:18472}}\n",
    );
    let wildcard_output = invoke(&wildcard, "check");
    assert!(
        !wildcard_output.status.success(),
        "wildcard overlap unexpectedly passed: {wildcard_output:?}"
    );
    let wildcard_error = String::from_utf8_lossy(&wildcard_output.stderr);
    assert!(wildcard_error.contains("0.0.0.0:18472"), "{wildcard_error}");
    assert!(
        wildcard_error.contains("listeners.wildcard"),
        "{wildcard_error}"
    );
    assert!(
        wildcard_error.contains("listeners.specific"),
        "{wildcard_error}"
    );

    let cross_family = write_config(
        directory.path(),
        "cross-family.yaml",
        "version: 2\nlisteners: {ipv6: {bind: '[::ffff:127.0.0.1]:18473'}, ipv4: {bind: 127.0.0.1:18473}}\n",
    );
    let cross_family_output = invoke(&cross_family, "check");
    assert!(
        !cross_family_output.status.success(),
        "cross-family overlap unexpectedly passed: {cross_family_output:?}"
    );
    let cross_family_error = String::from_utf8_lossy(&cross_family_output.stderr);
    assert!(
        cross_family_error.contains("[::ffff:127.0.0.1]:18473"),
        "{cross_family_error}"
    );
    assert!(
        cross_family_error.contains("listeners.ipv4"),
        "{cross_family_error}"
    );
    assert!(
        cross_family_error.contains("listeners.ipv6"),
        "{cross_family_error}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let real = directory.path().join("real");
        let link = directory.path().join("link");
        fs::create_dir(&real).expect("real socket directory");
        symlink(&real, &link).expect("socket directory symlink");
        let unix_alias = write_config(
            directory.path(),
            "unix-symlink.yaml",
            &format!(
                "version: 2\nlisteners:\n  one: {{bind: '{}'}}\n  two: {{bind: 'unix:{}'}}\n",
                link.join("pooler.sock").display(),
                real.join("pooler.sock").display()
            ),
        );
        let unix_alias_output = invoke(&unix_alias, "check");
        assert!(
            !unix_alias_output.status.success(),
            "Unix symlink alias unexpectedly passed: {unix_alias_output:?}"
        );
        let unix_alias_error = String::from_utf8_lossy(&unix_alias_output.stderr);
        assert!(
            unix_alias_error.contains("listeners.one"),
            "{unix_alias_error}"
        );
        assert!(
            unix_alias_error.contains("listeners.two"),
            "{unix_alias_error}"
        );
    }

    let management = write_config(
        directory.path(),
        "management.yaml",
        "version: 2\nmanagement: {bind: 127.0.0.1:18471}\nlisteners: {local: {bind: 127.0.0.1:18471}}\n",
    );
    let management_output = invoke(&management, "check");
    assert!(
        !management_output.status.success(),
        "management collision unexpectedly passed: {management_output:?}"
    );
    let management_error = String::from_utf8_lossy(&management_output.stderr);
    assert!(
        management_error.contains("management"),
        "{management_error}"
    );
    assert!(
        management_error.contains("listeners.local"),
        "{management_error}"
    );

    let ephemeral = write_config(
        directory.path(),
        "ephemeral.yaml",
        "version: 2\nmanagement: {bind: 127.0.0.1:0}\nlisteners: {one: {bind: 127.0.0.1:0}, two: {bind: 127.0.0.1:0}}\n",
    );
    let ephemeral_output = invoke(&ephemeral, "check");
    assert!(
        ephemeral_output.status.success(),
        "ephemeral binds were rejected: {}",
        String::from_utf8_lossy(&ephemeral_output.stderr)
    );
    assert_eq!(ephemeral_output.stdout, b"configuration is valid\n");
    assert!(
        ephemeral_output.stderr.is_empty(),
        "unexpected stderr: {ephemeral_output:?}"
    );
}
