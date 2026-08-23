//! Maintenance of the vendored per-model request-facts snapshot.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use pooler_model_catalog::{ModelFacts, ProviderCatalog, MODELS_DEV_CATALOG_URL};

/// Default location of the vendored snapshot inside a Pooler checkout.
pub const VENDORED_MODEL_FACTS_PATH: &str = "crates/pooler-model-catalog/data/model-facts.json";

/// Model-catalog data operations.
#[derive(Debug, Subcommand)]
pub enum CatalogCommand {
    /// Regenerate the vendored request-facts snapshot from the upstream catalog.
    Refresh {
        /// Upstream catalog URL. Must be HTTPS.
        #[arg(long, default_value = MODELS_DEV_CATALOG_URL)]
        url: String,
        /// Project an already-downloaded catalog document instead of fetching.
        #[arg(long)]
        from: Option<PathBuf>,
        /// Snapshot path to write or verify.
        #[arg(long, default_value = VENDORED_MODEL_FACTS_PATH)]
        output: PathBuf,
        /// Verify the snapshot is current without writing it.
        #[arg(long)]
        check: bool,
    },
    /// Print the request facts compiled into this build.
    Facts {
        /// Restrict output to one provider key.
        #[arg(long)]
        provider: Option<String>,
        /// Emit the snapshot as JSON instead of a summary.
        #[arg(long)]
        json: bool,
    },
}

/// Runs one catalog command.
pub fn run(command: CatalogCommand) -> Result<()> {
    match command {
        CatalogCommand::Refresh {
            url,
            from,
            output,
            check,
        } => refresh(&url, from.as_deref(), &output, check),
        CatalogCommand::Facts { provider, json } => facts(provider.as_deref(), json),
    }
}

fn refresh(url: &str, from: Option<&Path>, output: &Path, check: bool) -> Result<()> {
    let facts = match from {
        Some(path) => {
            let document = std::fs::read(path)
                .with_context(|| format!("could not read model catalog `{}`", path.display()))?;
            pooler_server::project_model_facts(&document, url)
                .context("could not project the model catalog")?
        }
        None => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to initialize the catalog refresh runtime")?;
            runtime
                .block_on(pooler_server::fetch_model_facts(url))
                .with_context(|| format!("could not refresh model facts from `{url}`"))?
        }
    };
    let rendered = facts
        .to_canonical_json()
        .context("could not render the model-facts snapshot")?;

    if check {
        let committed = std::fs::read_to_string(output).with_context(|| {
            format!("could not read model-facts snapshot `{}`", output.display())
        })?;
        if committed != rendered {
            bail!(
                "model-facts snapshot `{}` is stale; upstream digest is {} \
                 with {} model profiles across {} providers. Run `pooler catalog refresh`.",
                output.display(),
                facts.source_sha256(),
                facts.entry_count(),
                facts.provider_count(),
            );
        }
        println!(
            "model-facts snapshot is current ({} model profiles across {} providers, upstream digest {})",
            facts.entry_count(),
            facts.provider_count(),
            facts.source_sha256(),
        );
        return Ok(());
    }

    std::fs::write(output, rendered.as_bytes()).with_context(|| {
        format!(
            "could not write model-facts snapshot `{}`",
            output.display()
        )
    })?;
    println!(
        "wrote {} ({} model profiles across {} providers, {} upstream models, digest {})",
        output.display(),
        facts.entry_count(),
        facts.provider_count(),
        facts.upstream_model_count(),
        facts.source_sha256(),
    );
    Ok(())
}

/// Lists the providers this build can address without an explicit URL.
///
/// The environment variables are the ones each provider's own tooling reads,
/// so they are the names an operator most likely already has exported. They are
/// printed as a suggestion; configuration still names the secret it uses.
pub fn providers(search: Option<&str>, json: bool) -> Result<()> {
    let catalog = ProviderCatalog::builtin();
    let needle = search.map(str::to_ascii_lowercase);
    let matched = catalog
        .iter()
        .filter(|(id, provider)| match needle.as_deref() {
            Some(needle) => {
                id.to_ascii_lowercase().contains(needle)
                    || provider.name.to_ascii_lowercase().contains(needle)
            }
            None => true,
        })
        .collect::<Vec<_>>();

    if json {
        let rendered = matched
            .iter()
            .map(|(id, provider)| {
                serde_json::json!({
                    "id": id,
                    "name": provider.name,
                    "base_url": provider.base_url,
                    "env": provider.env,
                    "integration": provider.integration,
                })
            })
            .collect::<Vec<_>>();
        let mut rendered = serde_json::to_vec_pretty(&serde_json::json!({"providers": rendered}))
            .context("could not render the provider table")?;
        rendered.push(b'\n');
        write_stdout(&rendered)?;
        return Ok(());
    }

    if matched.is_empty() {
        println!("no provider matches that search");
        return Ok(());
    }
    let width = matched.iter().map(|(id, _)| id.len()).max().unwrap_or(0);
    for (id, provider) in &matched {
        let secret = provider
            .env
            .first()
            .map_or_else(String::new, |name| format!("  (env:{name})"));
        println!(
            "{id:width$}  {}  dialect={} discovery={} auth={}{}",
            provider.base_url,
            provider.integration.request_dialect,
            provider
                .integration
                .discovery_parser
                .as_deref()
                .unwrap_or("none"),
            provider.integration.auth_kind,
            secret
        );
    }
    println!();
    println!(
        "{} of {} providers shown. Use one with `known_provider: <id>` on an upstream.",
        matched.len(),
        catalog.len()
    );
    Ok(())
}

fn facts(provider: Option<&str>, json: bool) -> Result<()> {
    let facts = ModelFacts::builtin();
    if json {
        let rendered = facts
            .to_canonical_json()
            .context("could not render the model-facts snapshot")?;
        write_stdout(rendered.as_bytes())?;
        return Ok(());
    }
    if let Some(provider) = provider {
        if !facts.covers_provider(provider) {
            println!("{provider}: no recorded model profiles");
            return Ok(());
        }
    }
    println!("source: {}", facts.source_url());
    println!("upstream digest: {}", facts.source_sha256());
    println!("upstream models: {}", facts.upstream_model_count());
    println!(
        "recorded model profiles: {} across {} providers",
        facts.entry_count(),
        facts.provider_count()
    );
    Ok(())
}

/// Write command output without panicking when a downstream consumer closes
/// stdout early.
///
/// Rust's print macros panic when stdout closes early. CLI JSON output is
/// commonly piped into bounded consumers, so a broken pipe is a successful
/// early termination rather than an operator error.
fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    write_output(&mut stdout, bytes)
}

fn write_output<W: io::Write>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    if let Err(error) = writer.write_all(bytes) {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error).context("could not write catalog output");
    }
    if let Err(error) = writer.flush() {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error).context("could not flush catalog output");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn projecting_a_local_document_writes_a_snapshot_the_runtime_can_load() {
        let directory = tempfile::tempdir().expect("temporary snapshot directory");
        let document = directory.path().join("api.json");
        let output = directory.path().join("model-facts.json");
        std::fs::write(
            &document,
            br#"{"openai":{"models":{
              "rejects-temperature":{"temperature":false},
              "keeps-temperature":{"temperature":true}
            }}}"#,
        )
        .expect("upstream document");

        refresh(MODELS_DEV_CATALOG_URL, Some(&document), &output, false)
            .expect("projection writes the snapshot");

        let written = std::fs::read(&output).expect("snapshot written");
        let facts = ModelFacts::from_json(&written).expect("snapshot loads");
        assert_eq!(facts.entry_count(), 1);
        assert!(!facts
            .dialect("openai", "rejects-temperature")
            .temperature
            .is_accepted());

        refresh(MODELS_DEV_CATALOG_URL, Some(&document), &output, true)
            .expect("check passes against the snapshot it just wrote");
    }

    #[test]
    fn check_fails_when_the_snapshot_no_longer_matches_the_upstream_catalog() {
        let directory = tempfile::tempdir().expect("temporary snapshot directory");
        let document = directory.path().join("api.json");
        let output = directory.path().join("model-facts.json");
        std::fs::write(
            &document,
            br#"{"openai":{"models":{"rejects-temperature":{"temperature":false}}}}"#,
        )
        .expect("upstream document");
        refresh(MODELS_DEV_CATALOG_URL, Some(&document), &output, false).expect("initial snapshot");

        std::fs::write(
            &document,
            br#"{"openai":{"models":{
              "rejects-temperature":{"temperature":false},
              "also-rejects-temperature":{"temperature":false}
            }}}"#,
        )
        .expect("changed upstream document");

        let error = refresh(MODELS_DEV_CATALOG_URL, Some(&document), &output, true)
            .expect_err("stale snapshot is reported");
        assert!(error.to_string().contains("is stale"));
    }

    #[test]
    fn the_committed_snapshot_is_the_snapshot_compiled_into_this_build() {
        let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(VENDORED_MODEL_FACTS_PATH);
        let text = std::fs::read(&committed).expect("committed snapshot is readable");

        assert_eq!(
            ModelFacts::from_json(&text).expect("committed snapshot loads"),
            *ModelFacts::builtin()
        );
    }

    #[test]
    fn broken_pipe_is_treated_as_successful_json_termination() {
        struct BrokenPipeWriter;

        impl io::Write for BrokenPipeWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        write_output(&mut BrokenPipeWriter, br#"{"models":[]}"#)
            .expect("broken pipe should stop JSON output cleanly");
    }
}
