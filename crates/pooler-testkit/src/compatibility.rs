//! Deterministic compatibility-manifest loading and report rendering.
//!
//! The manifest is intentionally separate from runtime configuration.  It is
//! a release artifact that records which sanitized fixtures exist and what
//! evidence they represent; a local reference fixture is never presented as
//! current client or provider compatibility.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current compatibility-manifest schema version.
pub const COMPATIBILITY_MANIFEST_SCHEMA_VERSION: u32 = 1;

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

    /// Checks that all declared fixture paths exist relative to `manifest`.
    pub fn validate_fixture_paths(&self, manifest: &Path) -> Result<(), CompatibilityError> {
        let base = manifest.parent().unwrap_or_else(|| Path::new("."));
        for entry in &self.entries {
            let path = base.join(&entry.fixture);
            if !path.is_file() {
                return Err(CompatibilityError::MissingFixture {
                    path,
                    manifest: manifest.to_owned(),
                });
            }
        }
        Ok(())
    }
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
        "Reference-only rows do not claim compatibility with a current client or live provider.\n\n",
        "| Adapter | Protocol | Fixture version | Equivalence | Evidence | Provenance | Notes | Fixture |\n",
        "| --- | --- | --- | --- | --- | --- | --- | --- |\n",
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

        assert!(error.to_string().contains("duplicate fixture declaration"));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut manifest = manifest();
        manifest.schema_version += 1;

        let error = manifest.validate().expect_err("unknown version must fail");

        assert!(error.to_string().contains("schema version"));
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
        for target in ["sse", "connect", "json_patch", "overlay", "tool_deltas"] {
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
}
