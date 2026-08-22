use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pooler_testkit::{
    capture_fixture, write_captured_fixture, CaptureOptions, Equivalence, Fixture,
};
use serde::Serialize;
use serde_json::Value;

use crate::FixtureCommand;

/// A stable, machine-readable result for one fixture replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReplayReport {
    pub path: String,
    pub id: String,
    pub equivalence: String,
    pub status: ReplayStatus,
    pub equivalent: bool,
    pub differences: Vec<String>,
}

/// Outcome of one fixture replay attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    /// The expected and actual fixture representations matched.
    Passed,
    /// The expected and actual fixture representations differed.
    Failed,
    /// No actual fixture or executable adapter was supplied, so no comparison
    /// was performed.
    Skipped,
}

/// Run a fixture subcommand without loading server configuration or opening a
/// management store.
pub fn run(command: FixtureCommand) -> Result<()> {
    match command {
        FixtureCommand::Replay { path, actual } => replay(&path, actual.as_deref()),
        FixtureCommand::Capture {
            input,
            output,
            include_bodies,
            max_body_bytes,
        } => capture(&input, &output, include_bodies, max_body_bytes),
        FixtureCommand::Report {
            manifest,
            format,
            output,
        } => super::fixture_report(&manifest, format, output.as_deref()),
    }
}

fn replay(path: &Path, actual_root: Option<&Path>) -> Result<()> {
    let reports = replay_reports(path, actual_root)?;
    let mut failed = false;
    let mut skipped = false;
    for report in &reports {
        if report.status == ReplayStatus::Failed {
            failed = true;
        }
        if report.status == ReplayStatus::Skipped {
            skipped = true;
        }
        println!(
            "{}",
            serde_json::to_string(report).context("could not serialize fixture report")?
        );
    }
    if failed {
        bail!("one or more fixture replays were not equivalent")
    }
    if skipped {
        bail!("one or more fixture replays were skipped; provide --actual")
    }
    Ok(())
}

/// Load one fixture or a deterministic, recursively sorted fixture directory.
pub fn replay_reports(path: &Path, actual_root: Option<&Path>) -> Result<Vec<ReplayReport>> {
    let paths = fixture_paths(path)?;
    let mut reports = Vec::with_capacity(paths.len());
    for fixture_path in paths {
        let actual_path = actual_root.map(|root| actual_path(path, root, &fixture_path));
        reports.push(replay_one(&fixture_path, actual_path.as_deref())?);
    }
    Ok(reports)
}

fn replay_one(path: &Path, actual_path: Option<&Path>) -> Result<ReplayReport> {
    let bytes =
        fs::read(path).with_context(|| format!("could not read fixture `{}`", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("fixture `{}` is not valid JSON", path.display()))?;
    let metadata = metadata_from_value(&value, path)?;

    let Some(actual_path) = actual_path else {
        return Ok(ReplayReport {
            path: path.display().to_string(),
            id: metadata.0,
            equivalence: metadata.1,
            status: ReplayStatus::Skipped,
            equivalent: false,
            differences: vec!["actual_fixture_required".to_owned()],
        });
    };

    let (equivalent, differences) = match serde_json::from_value::<Fixture>(value.clone()) {
        Ok(expected) => {
            let actual_bytes = fs::read(actual_path).with_context(|| {
                format!("could not read actual fixture `{}`", actual_path.display())
            })?;
            let actual = serde_json::from_slice::<Fixture>(&actual_bytes).with_context(|| {
                format!(
                    "actual fixture `{}` has an unsupported schema",
                    actual_path.display()
                )
            })?;
            let report = expected.compare(&actual);
            (report.equivalent, report.differences)
        }
        Err(_) => (false, vec!["fixture_schema".to_owned()]),
    };

    Ok(ReplayReport {
        path: path.display().to_string(),
        id: metadata.0,
        equivalence: metadata.1,
        status: if equivalent {
            ReplayStatus::Passed
        } else {
            ReplayStatus::Failed
        },
        equivalent,
        differences,
    })
}

fn capture(input: &Path, output: &Path, include_bodies: bool, max_body_bytes: usize) -> Result<()> {
    if max_body_bytes == 0 {
        bail!("--max-body-bytes must be greater than zero")
    }
    let bytes =
        fs::read(input).with_context(|| format!("could not read fixture `{}`", input.display()))?;
    let fixture: Fixture = serde_json::from_slice(&bytes)
        .with_context(|| format!("fixture `{}` has an unsupported schema", input.display()))?;
    let options = CaptureOptions {
        include_bodies,
        max_body_bytes,
        ..CaptureOptions::default()
    };
    let captured = capture_fixture(&fixture, &options);
    write_captured_fixture(output, &captured)
        .with_context(|| format!("could not write capture `{}`", output.display()))?;
    Ok(())
}

fn fixture_paths(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_owned()]);
    }
    if !path.is_dir() {
        bail!(
            "fixture path `{}` is not a file or directory",
            path.display()
        )
    }

    let mut paths = Vec::new();
    collect_fixture_paths(path, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        bail!(
            "fixture directory `{}` contains no JSON fixtures",
            path.display()
        )
    }
    Ok(paths)
}

fn collect_fixture_paths(path: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("could not read fixture directory `{}`", path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("could not enumerate fixture directory `{}`", path.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let entry_type = entry
            .file_type()
            .with_context(|| format!("could not inspect `{}`", entry.path().display()))?;
        if entry_type.is_symlink() {
            continue;
        }
        let entry_path = entry.path();
        if entry_type.is_dir() {
            collect_fixture_paths(&entry_path, paths)?;
        } else if entry_type.is_file()
            && entry_path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            && entry_path
                .file_name()
                .is_none_or(|name| name != "manifest.json")
        {
            paths.push(entry_path);
        }
    }
    Ok(())
}

fn actual_path(root: &Path, actual_root: &Path, expected_path: &Path) -> PathBuf {
    if actual_root.is_file() {
        return actual_root.to_owned();
    }
    if root.is_file() {
        return actual_root.join(
            expected_path
                .file_name()
                .unwrap_or(expected_path.as_os_str()),
        );
    }
    expected_path.strip_prefix(root).map_or_else(
        |_| actual_root.join(expected_path),
        |relative| actual_root.join(relative),
    )
}

fn metadata_from_value(value: &Value, path: &Path) -> Result<(String, String)> {
    let object = value.as_object().ok_or_else(|| {
        anyhow::anyhow!("fixture `{}` must contain a JSON object", path.display())
    })?;
    let metadata = object.get("metadata").and_then(Value::as_object);
    let id = metadata
        .and_then(|metadata| metadata.get("id"))
        .or_else(|| object.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("fixture `{}` has no id", path.display()))?;
    let equivalence = metadata
        .and_then(|metadata| metadata.get("equivalence"))
        .or_else(|| object.get("equivalence"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| Equivalence::default().name());
    Ok((id.to_owned(), equivalence.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use pooler_testkit::{Equivalence, FixtureMetadata, ScriptedRequest};

    fn fixture() -> Fixture {
        Fixture {
            metadata: FixtureMetadata::new("fixture", Equivalence::JsonStructural),
            downstream_request: Some(ScriptedRequest::new("POST", "/v1")),
            ..Fixture::default()
        }
    }

    #[test]
    fn replay_reports_are_deterministic_and_sorted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for name in ["b.json", "a.json"] {
            fs::write(
                directory.path().join(name),
                serde_json::to_vec(&fixture()).expect("fixture serializes"),
            )
            .expect("fixture writes");
        }
        let first = replay_reports(directory.path(), None).expect("fixtures replay");
        let second = replay_reports(directory.path(), None).expect("fixtures replay");
        assert_eq!(first, second);
        assert!(first[0].path.ends_with("a.json"));
        assert!(first
            .iter()
            .all(|report| report.status == ReplayStatus::Skipped));
        assert!(first.iter().all(|report| !report.equivalent));
    }

    #[test]
    fn replay_reports_structured_differences_from_an_actual_fixture() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected_path = directory.path().join("expected.json");
        let actual_path = directory.path().join("actual.json");
        fs::write(
            &expected_path,
            serde_json::to_vec(&fixture()).expect("fixture serializes"),
        )
        .expect("expected fixture writes");
        let mut actual = fixture();
        actual.metadata.id = "different".to_owned();
        fs::write(
            &actual_path,
            serde_json::to_vec(&actual).expect("fixture serializes"),
        )
        .expect("actual fixture writes");

        let reports = replay_reports(&expected_path, Some(&actual_path)).expect("replay reports");
        assert!(!reports[0].equivalent);
        assert_eq!(reports[0].differences, vec!["metadata.id"]);
    }

    #[test]
    fn replay_without_actual_is_skipped_instead_of_self_comparing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fixture.json");
        fs::write(
            &path,
            serde_json::to_vec(&fixture()).expect("fixture serializes"),
        )
        .expect("fixture writes");
        let reports = replay_reports(&path, None).expect("fixture replays");
        assert_eq!(reports[0].id, "fixture");
        assert_eq!(reports[0].status, ReplayStatus::Skipped);
        assert!(!reports[0].equivalent);
        assert_eq!(
            reports[0].differences,
            vec!["actual_fixture_required".to_owned()]
        );
        let error = replay(&path, None).expect_err("skipped replay must fail clearly");
        assert!(error.to_string().contains("provide --actual"));
    }

    #[test]
    fn adapter_specific_fixture_without_actual_is_skipped() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("adapter.json");
        fs::write(
            &path,
            br#"{"id":"adapter-fixture","equivalence":"protobuf_semantic"}"#,
        )
        .expect("fixture writes");

        let reports = replay_reports(&path, None).expect("fixture metadata is readable");

        assert_eq!(reports[0].status, ReplayStatus::Skipped);
        assert!(!reports[0].equivalent);
    }

    #[test]
    fn capture_is_opt_in_and_bounded() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let capture_directory = directory
            .path()
            .canonicalize()
            .expect("canonical temporary directory");
        #[cfg(unix)]
        fs::set_permissions(&capture_directory, fs::Permissions::from_mode(0o700))
            .expect("private capture directory");
        let input = capture_directory.join("fixture.json");
        let output = capture_directory.join("capture.json");
        let explicit_output = capture_directory.join("capture-with-bodies.json");
        let mut fixture = fixture();
        fixture.downstream_request = Some(
            ScriptedRequest::new("POST", "/v1")
                .with_header("content-type", "application/json")
                .with_body(br#"{"password":"capture-secret"}"#.to_vec()),
        );
        fs::write(
            &input,
            serde_json::to_vec(&fixture).expect("fixture serializes"),
        )
        .expect("fixture writes");

        capture(&input, &output, false, 1024).expect("default capture");
        let default_contents = fs::read_to_string(&output).expect("capture reads");
        assert!(!default_contents.contains("capture-secret"));
        assert!(!default_contents.contains("\"value\""));

        capture(&input, &explicit_output, true, 1024).expect("explicit capture");
        let explicit_contents = fs::read_to_string(&explicit_output).expect("capture reads");
        assert!(!explicit_contents.contains("capture-secret"));
        assert!(explicit_contents.contains("[REDACTED]"));
    }
}
