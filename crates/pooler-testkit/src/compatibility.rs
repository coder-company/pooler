//! Deterministic compatibility-manifest loading and report rendering.
//!
//! The manifest is intentionally separate from runtime configuration.  It is
//! a release artifact that records which sanitized fixtures exist and what
//! evidence they represent; a local reference fixture is never presented as
//! current client or provider compatibility.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current compatibility-manifest schema version.
pub const COMPATIBILITY_MANIFEST_SCHEMA_VERSION: u32 = 1;

const COMPATIBILITY_FIXTURE_CLAIM_SCHEMA_VERSION: u32 = 1;

/// A compatibility manifest containing versioned fixture declarations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityManifest {
    /// Version of the manifest shape, not of an external client.
    pub schema_version: u32,
    /// Fixture declarations included in the report.
    pub entries: Vec<CompatibilityEntry>,
}

/// One adapter/protocol fixture declaration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityEntry {
    /// Pooler adapter or route family covered by the fixture.
    pub adapter: String,
    /// Protocol layout exercised by the fixture.
    pub protocol: String,
    /// Version of the fixture contract.
    pub version: String,
    /// Path relative to the manifest file.
    pub fixture: PathBuf,
    /// Comparison relation used by the fixture.
    pub equivalence: String,
    /// What the fixture proves.  This field deliberately distinguishes local
    /// evidence from compatibility claims.
    pub status: CompatibilityStatus,
    /// Sanitized source or provenance description.
    #[serde(default)]
    pub source: String,
    /// Additional constraints or intentional differences.
    #[serde(default)]
    pub notes: Vec<String>,
    /// Capabilities exercised by the fixture or route family.
    #[serde(default)]
    pub supported_capabilities: Vec<String>,
    /// Capabilities intentionally unsupported or not evidenced by this row.
    #[serde(default)]
    pub unsupported_capabilities: Vec<String>,
}

/// Evidence level recorded for one compatibility fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    /// No client or provider compatibility evidence is available yet.
    NotEstablished,
    /// Fixture is grounded in a sanitized local reference implementation.
    SanitizedLocalReference,
    /// Fixture is grounded in a sanitized cross-language implementation.
    SanitizedCrossLanguage,
    /// A current client conformance run has been recorded.
    CurrentClientConformance,
    /// A live provider conformance run has been recorded.
    LiveProviderConformance,
}

impl CompatibilityStatus {
    /// Human-readable status suitable for a release report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotEstablished => "not established",
            Self::SanitizedLocalReference => {
                "sanitized local reference (compatibility not claimed)"
            }
            Self::SanitizedCrossLanguage => {
                "sanitized cross-language reference (compatibility not claimed)"
            }
            Self::CurrentClientConformance => "current client conformance",
            Self::LiveProviderConformance => "live provider conformance",
        }
    }

    /// Returns whether the status is reference evidence rather than a current
    /// compatibility claim.
    #[must_use]
    pub const fn is_reference_only(self) -> bool {
        matches!(
            self,
            Self::NotEstablished | Self::SanitizedLocalReference | Self::SanitizedCrossLanguage
        )
    }
}

/// Errors returned by compatibility-manifest tooling.
#[derive(Debug, Error)]
pub enum CompatibilityError {
    /// The manifest could not be read.
    #[error("could not read compatibility manifest `{path}`: {source}")]
    Read {
        /// Path that was read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The manifest was not valid JSON.
    #[error("invalid compatibility manifest `{path}`: {source}")]
    Parse {
        /// Path that was parsed.
        path: PathBuf,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// The manifest failed semantic validation.
    #[error("invalid compatibility manifest: {0}")]
    Invalid(String),
    /// A declared fixture file is missing.
    #[error("compatibility fixture `{path}` declared by `{manifest}` does not exist")]
    MissingFixture {
        /// Resolved fixture path.
        path: PathBuf,
        /// Manifest path.
        manifest: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityFixtureClaim {
    schema_version: u32,
    adapter: String,
    protocol: String,
    version: String,
    equivalence: String,
    exercised_capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClaimedCompatibilityFixture {
    compatibility: CompatibilityFixtureClaim,
}

impl CompatibilityManifest {
    /// Validates the manifest shape and duplicate declarations.
    pub fn validate(&self) -> Result<(), CompatibilityError> {
        if self.schema_version != COMPATIBILITY_MANIFEST_SCHEMA_VERSION {
            return Err(CompatibilityError::Invalid(format!(
                "schema version {} is unsupported; expected {}",
                self.schema_version, COMPATIBILITY_MANIFEST_SCHEMA_VERSION
            )));
        }
        if self.entries.is_empty() {
            return Err(CompatibilityError::Invalid(
                "manifest must contain at least one fixture".to_owned(),
            ));
        }

        let mut keys = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for entry in &self.entries {
            for (name, value) in [
                ("adapter", entry.adapter.as_str()),
                ("protocol", entry.protocol.as_str()),
                ("version", entry.version.as_str()),
                ("fixture", entry.fixture.to_string_lossy().as_ref()),
                ("equivalence", entry.equivalence.as_str()),
            ] {
                if value.trim().is_empty() {
                    return Err(CompatibilityError::Invalid(format!(
                        "entry `{}` has an empty {name}",
                        entry.adapter
                    )));
                }
            }
            if entry.source.trim().is_empty() {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` has an empty source",
                    entry.adapter
                )));
            }
            if entry.supported_capabilities.is_empty() {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` has no supported capabilities",
                    entry.adapter
                )));
            }
            if entry
                .supported_capabilities
                .iter()
                .any(|capability| capability.trim().is_empty())
                || entry
                    .unsupported_capabilities
                    .iter()
                    .any(|capability| capability.trim().is_empty())
            {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` contains an empty capability",
                    entry.adapter
                )));
            }
            let supported = unique_capabilities(
                &entry.adapter,
                "supported_capabilities",
                &entry.supported_capabilities,
            )?;
            let unsupported = unique_capabilities(
                &entry.adapter,
                "unsupported_capabilities",
                &entry.unsupported_capabilities,
            )?;
            if entry
                .unsupported_capabilities
                .iter()
                .any(|capability| supported.contains(capability))
            {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` lists a capability as both supported and unsupported",
                    entry.adapter
                )));
            }
            let live_capability = |capability: &&String| {
                capability.as_str() == "live_provider"
                    || capability.as_str() == "live_native_provider"
            };
            let supports_live_provider = supported.iter().any(live_capability);
            if supports_live_provider
                && entry.status != CompatibilityStatus::LiveProviderConformance
            {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` claims live-provider capability without live-provider conformance",
                    entry.adapter
                )));
            }
            if entry.status == CompatibilityStatus::LiveProviderConformance
                && !supports_live_provider
            {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` records live-provider conformance without a live-provider capability",
                    entry.adapter
                )));
            }
            if matches!(
                entry.status,
                CompatibilityStatus::CurrentClientConformance
                    | CompatibilityStatus::LiveProviderConformance
            ) && !entry
                .notes
                .iter()
                .any(|note| note.trim_start().starts_with("Replay:"))
            {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` makes a conformance claim without a Replay note",
                    entry.adapter
                )));
            }
            if unsupported.iter().any(live_capability)
                && entry.status == CompatibilityStatus::LiveProviderConformance
            {
                return Err(CompatibilityError::Invalid(format!(
                    "entry `{}` records live-provider conformance while listing it as unsupported",
                    entry.adapter
                )));
            }
            let identity = format!(
                "{}\u{1f}{}\u{1f}{}",
                entry.adapter, entry.protocol, entry.version
            );
            if !identities.insert(identity) {
                return Err(CompatibilityError::Invalid(format!(
                    "duplicate compatibility identity for `{}` / `{}` / `{}`",
                    entry.adapter, entry.protocol, entry.version
                )));
            }
            let key = format!(
                "{}\u{1f}{}\u{1f}{}",
                entry.adapter,
                entry.protocol,
                entry.fixture.display()
            );
            if !keys.insert(key) {
                return Err(CompatibilityError::Invalid(format!(
                    "duplicate fixture declaration for `{}` / `{}` / `{}`",
                    entry.adapter,
                    entry.protocol,
                    entry.fixture.display()
                )));
            }
        }
        Ok(())
    }

    /// Checks that declared fixture paths resolve inside the manifest's Cargo
    /// workspace and that no two rows resolve to the same file.
    pub fn validate_fixture_paths(&self, manifest: &Path) -> Result<(), CompatibilityError> {
        let base = manifest
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_base = fs::canonicalize(base).map_err(|source| CompatibilityError::Read {
            path: base.to_owned(),
            source,
        })?;
        let workspace_root = find_workspace_root(&canonical_base).ok_or_else(|| {
            CompatibilityError::Invalid(format!(
                "compatibility manifest `{}` is not inside a Cargo workspace",
                manifest.display()
            ))
        })?;
        let canonical_manifest =
            fs::canonicalize(manifest).map_err(|source| CompatibilityError::Read {
                path: manifest.to_owned(),
                source,
            })?;
        if !canonical_manifest.starts_with(&workspace_root) {
            return Err(CompatibilityError::Invalid(format!(
                "compatibility manifest `{}` resolves outside workspace `{}`",
                manifest.display(),
                workspace_root.display()
            )));
        }

        let mut canonical_targets = BTreeMap::new();
        for entry in &self.entries {
            if entry.fixture.is_absolute() {
                return Err(CompatibilityError::Invalid(format!(
                    "compatibility fixture path `{}` must be relative",
                    entry.fixture.display()
                )));
            }
            let path = base.join(&entry.fixture);
            if !path.is_file() {
                return Err(CompatibilityError::MissingFixture {
                    path,
                    manifest: manifest.to_owned(),
                });
            }
            let canonical = fs::canonicalize(&path).map_err(|source| CompatibilityError::Read {
                path: path.clone(),
                source,
            })?;
            if !canonical.starts_with(&workspace_root) {
                return Err(CompatibilityError::Invalid(format!(
                    "compatibility fixture `{}` resolves outside workspace `{}`",
                    entry.fixture.display(),
                    workspace_root.display()
                )));
            }
            if let Some(first) = canonical_targets.insert(canonical.clone(), &entry.fixture) {
                return Err(CompatibilityError::Invalid(format!(
                    "compatibility fixtures `{}` and `{}` resolve to the same file `{}`",
                    first.display(),
                    entry.fixture.display(),
                    canonical.display()
                )));
            }
            if matches!(
                entry.status,
                CompatibilityStatus::CurrentClientConformance
                    | CompatibilityStatus::LiveProviderConformance
            ) {
                validate_fixture_claim(entry, &canonical)?;
            }
        }
        Ok(())
    }
}

fn unique_capabilities<'a>(
    adapter: &str,
    field: &str,
    capabilities: &'a [String],
) -> Result<BTreeSet<&'a String>, CompatibilityError> {
    let unique = capabilities.iter().collect::<BTreeSet<_>>();
    if unique.len() != capabilities.len() {
        return Err(CompatibilityError::Invalid(format!(
            "entry `{adapter}` contains duplicate values in {field}"
        )));
    }
    Ok(unique)
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find_map(|candidate| {
        let cargo_manifest = candidate.join("Cargo.toml");
        let contents = fs::read_to_string(cargo_manifest).ok()?;
        contents
            .lines()
            .any(|line| line.trim() == "[workspace]")
            .then(|| candidate.to_owned())
    })
}

fn validate_fixture_claim(
    entry: &CompatibilityEntry,
    fixture: &Path,
) -> Result<(), CompatibilityError> {
    let bytes = fs::read(fixture).map_err(|source| CompatibilityError::Read {
        path: fixture.to_owned(),
        source,
    })?;
    let envelope: ClaimedCompatibilityFixture =
        serde_json::from_slice(&bytes).map_err(|error| {
            CompatibilityError::Invalid(format!(
                "conformance fixture `{}` has no valid typed compatibility envelope: {error}",
                fixture.display()
            ))
        })?;
    let claim = envelope.compatibility;
    if claim.schema_version != COMPATIBILITY_FIXTURE_CLAIM_SCHEMA_VERSION {
        return Err(CompatibilityError::Invalid(format!(
            "conformance fixture `{}` uses compatibility envelope schema {}; expected {}",
            fixture.display(),
            claim.schema_version,
            COMPATIBILITY_FIXTURE_CLAIM_SCHEMA_VERSION
        )));
    }
    for (field, actual, expected) in [
        ("adapter", claim.adapter.as_str(), entry.adapter.as_str()),
        ("protocol", claim.protocol.as_str(), entry.protocol.as_str()),
        ("version", claim.version.as_str(), entry.version.as_str()),
        (
            "equivalence",
            claim.equivalence.as_str(),
            entry.equivalence.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(CompatibilityError::Invalid(format!(
                "conformance fixture `{}` {field} `{actual}` does not match manifest `{expected}`",
                fixture.display()
            )));
        }
    }
    let claimed = unique_capabilities(
        &entry.adapter,
        "compatibility.exercised_capabilities",
        &claim.exercised_capabilities,
    )?;
    let manifest = entry.supported_capabilities.iter().collect::<BTreeSet<_>>();
    if claimed != manifest {
        return Err(CompatibilityError::Invalid(format!(
            "conformance fixture `{}` exercised capabilities do not match the manifest claim",
            fixture.display()
        )));
    }
    Ok(())
}

/// Loads and validates a JSON compatibility manifest.
pub fn load_compatibility_manifest(
    path: impl AsRef<Path>,
) -> Result<CompatibilityManifest, CompatibilityError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| CompatibilityError::Read {
        path: path.to_owned(),
        source,
    })?;
    let manifest: CompatibilityManifest =
        serde_json::from_slice(&bytes).map_err(|source| CompatibilityError::Parse {
            path: path.to_owned(),
            source,
        })?;
    manifest.validate()?;
    manifest.validate_fixture_paths(path)?;
    Ok(manifest)
}

/// Renders a stable, readable Markdown matrix.
#[must_use]
pub fn render_compatibility_matrix(manifest: &CompatibilityManifest) -> String {
    let mut entries = manifest.entries.clone();
    entries.sort_by(|left, right| {
        (&left.adapter, &left.protocol, &left.version, &left.fixture).cmp(&(
            &right.adapter,
            &right.protocol,
            &right.version,
            &right.fixture,
        ))
    });

    let mut output = String::from(concat!(
        "# Compatibility matrix\n\n",
        "This report is generated from `fixtures/compatibility/manifest.json`. ",
        "Reference-only rows do not claim compatibility with a current client or live provider. ",
        "Supported capabilities describe the exercised Pooler surface; unsupported capabilities ",
        "are not silently inferred from a route name.\n\n",
        "| Adapter | Protocol | Fixture version | Equivalence | Evidence | Provenance | Supported capabilities | Unsupported capabilities | Notes | Fixture |\n",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    ));
    for entry in entries {
        output.push_str("| ");
        output.push_str(&markdown_cell(&entry.adapter));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.protocol));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.version));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.equivalence));
        output.push_str(" | ");
        output.push_str(&markdown_cell(entry.status.label()));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.source));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.supported_capabilities.join(", ")));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.unsupported_capabilities.join(", ")));
        output.push_str(" | ");
        output.push_str(&markdown_cell(&entry.notes.join("; ")));
        output.push_str(" | ");
        output.push('`');
        output.push_str(&entry.fixture.to_string_lossy());
        output.push_str("` |\n");
    }
    output
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn manifest() -> CompatibilityManifest {
        CompatibilityManifest {
            schema_version: COMPATIBILITY_MANIFEST_SCHEMA_VERSION,
            entries: vec![CompatibilityEntry {
                adapter: "factory".to_owned(),
                protocol: "language-model-v3".to_owned(),
                version: "v3".to_owned(),
                fixture: PathBuf::from("factory.json"),
                equivalence: "event_semantic".to_owned(),
                status: CompatibilityStatus::SanitizedLocalReference,
                source: "sanitized local bridge".to_owned(),
                notes: Vec::new(),
                supported_capabilities: vec!["text".to_owned()],
                unsupported_capabilities: vec!["live_provider".to_owned()],
            }],
        }
    }

    #[test]
    fn matrix_is_deterministic_and_does_not_claim_reference_compatibility() {
        let report = render_compatibility_matrix(&manifest());

        assert!(report.contains("sanitized local reference (compatibility not claimed)"));
        assert!(!report.contains("current client conformance"));
        assert_eq!(report, render_compatibility_matrix(&manifest()));
    }

    #[test]
    fn duplicate_entries_are_rejected() {
        let mut manifest = manifest();
        manifest.entries.push(manifest.entries[0].clone());

        let error = manifest.validate().expect_err("duplicate must fail");

        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut manifest = manifest();
        manifest.schema_version += 1;

        let error = manifest.validate().expect_err("unknown version must fail");

        assert!(error.to_string().contains("schema version"));
    }

    #[test]
    fn duplicate_capabilities_and_unbacked_live_claims_are_rejected() {
        let mut duplicate = manifest();
        duplicate.entries[0]
            .supported_capabilities
            .push("text".to_owned());
        assert!(duplicate
            .validate()
            .expect_err("duplicate capability must fail")
            .to_string()
            .contains("duplicate values"));

        let mut unbacked = manifest();
        unbacked.entries[0].unsupported_capabilities.clear();
        unbacked.entries[0]
            .supported_capabilities
            .push("live_provider".to_owned());
        assert!(unbacked
            .validate()
            .expect_err("reference evidence cannot claim live provider")
            .to_string()
            .contains("without live-provider conformance"));
    }

    #[test]
    fn duplicate_canonical_fixture_targets_are_rejected() {
        let workspace = compatibility_workspace();
        let fixture = workspace.path().join("fixtures/data/reference.json");
        fs::create_dir_all(fixture.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(&fixture, b"{}").expect("fixture");
        let mut manifest = manifest();
        manifest.entries[0].fixture = PathBuf::from("../data/reference.json");
        let mut duplicate = manifest.entries[0].clone();
        duplicate.adapter = "other".to_owned();
        duplicate.version = "v2".to_owned();
        duplicate.fixture = PathBuf::from("../data/../data/reference.json");
        manifest.entries.push(duplicate);
        let manifest_path = write_manifest(&workspace, &manifest);

        let error =
            load_compatibility_manifest(manifest_path).expect_err("canonical duplicate must fail");
        assert!(error.to_string().contains("resolve to the same file"));
    }

    #[test]
    fn conformance_fixture_claim_must_match_manifest_identity_and_capabilities() {
        let workspace = compatibility_workspace();
        let fixture = workspace.path().join("fixtures/data/current.json");
        fs::create_dir_all(fixture.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(
            &fixture,
            br#"{
                "compatibility": {
                    "schema_version": 1,
                    "adapter": "factory",
                    "protocol": "language-model-v3",
                    "version": "wrong",
                    "equivalence": "event_semantic",
                    "exercised_capabilities": ["text"]
                }
            }"#,
        )
        .expect("fixture");
        let mut manifest = manifest();
        let entry = &mut manifest.entries[0];
        entry.fixture = PathBuf::from("../data/current.json");
        entry.status = CompatibilityStatus::CurrentClientConformance;
        entry.notes = vec!["Replay: cargo test current".to_owned()];
        let manifest_path = write_manifest(&workspace, &manifest);

        let error = load_compatibility_manifest(manifest_path)
            .expect_err("claim identity mismatch must fail");
        assert!(error.to_string().contains("version `wrong`"));
    }

    #[test]
    fn fixture_parent_traversal_outside_workspace_is_rejected() {
        let workspace = compatibility_workspace();
        let outside = tempfile::tempdir().expect("outside directory");
        let outside_fixture = outside.path().join("outside.json");
        fs::write(&outside_fixture, b"{}").expect("outside fixture");
        let manifest_directory = workspace.path().join("fixtures/compatibility");
        let relative = pathdiff_for_test(&manifest_directory, &outside_fixture);
        let mut manifest = manifest();
        manifest.entries[0].fixture = relative;
        let manifest_path = write_manifest(&workspace, &manifest);

        let error =
            load_compatibility_manifest(manifest_path).expect_err("fixture traversal must fail");
        assert!(error.to_string().contains("resolves outside workspace"));
    }

    #[cfg(unix)]
    #[test]
    fn fixture_symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let workspace = compatibility_workspace();
        let outside = tempfile::tempdir().expect("outside directory");
        let outside_fixture = outside.path().join("outside.json");
        fs::write(&outside_fixture, b"{}").expect("outside fixture");
        let link = workspace.path().join("fixtures/data/link.json");
        fs::create_dir_all(link.parent().expect("link parent")).expect("link directory");
        symlink(&outside_fixture, &link).expect("fixture symlink");
        let mut manifest = manifest();
        manifest.entries[0].fixture = PathBuf::from("../data/link.json");
        let manifest_path = write_manifest(&workspace, &manifest);

        let error = load_compatibility_manifest(manifest_path)
            .expect_err("fixture symlink escape must fail");
        assert!(error.to_string().contains("resolves outside workspace"));
    }

    #[test]
    fn checked_in_matrix_matches_the_manifest() {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/compatibility/manifest.json");
        let matrix_path = manifest_path.with_file_name("MATRIX.md");
        let manifest = load_compatibility_manifest(&manifest_path).expect("manifest is valid");
        let expected = render_compatibility_matrix(&manifest);
        let actual = fs::read_to_string(matrix_path).expect("checked-in matrix is readable");

        assert_eq!(actual, expected);
    }

    #[test]
    fn cargo_fuzz_manifest_declares_each_seed_boundary() {
        let fuzz_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
        let manifest = fs::read_to_string(fuzz_root.join("Cargo.toml"))
            .expect("cargo-fuzz manifest is readable");

        assert!(manifest.contains("cargo-fuzz = true"));
        for target in [
            "sse",
            "connect",
            "json_patch",
            "overlay",
            "tool_deltas",
            "decompression",
            "route_match",
            "reasoning_state",
        ] {
            assert!(manifest.contains(&format!("name = \"{target}\"")));
            assert!(
                fuzz_root
                    .join("fuzz_targets")
                    .join(format!("{target}.rs"))
                    .is_file(),
                "missing cargo-fuzz target {target}"
            );
        }
    }

    fn compatibility_workspace() -> TempDir {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        fs::write(
            workspace.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\n",
        )
        .expect("workspace manifest");
        fs::create_dir_all(workspace.path().join("fixtures/compatibility"))
            .expect("compatibility directory");
        workspace
    }

    fn write_manifest(workspace: &TempDir, manifest: &CompatibilityManifest) -> PathBuf {
        let path = workspace
            .path()
            .join("fixtures/compatibility/manifest.json");
        fs::write(
            &path,
            serde_json::to_vec(manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
        path
    }

    fn pathdiff_for_test(base: &Path, target: &Path) -> PathBuf {
        let base = base.components().collect::<Vec<_>>();
        let target = target.components().collect::<Vec<_>>();
        let shared = base
            .iter()
            .zip(&target)
            .take_while(|(left, right)| left == right)
            .count();
        let mut relative = PathBuf::new();
        for _ in shared..base.len() {
            relative.push("..");
        }
        for component in &target[shared..] {
            relative.push(component.as_os_str());
        }
        relative
    }
}
