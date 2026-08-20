//! Pooler's command-line interface.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pooler_config::{Config, ConfigCandidate, ConfigWatcher};
use pooler_http::{NativeRuntime, PoolingCoordinator};
use pooler_store::{SqliteOAuthTokenStore, SqliteStore};

mod auth;
mod catalog;
mod doctor;
mod fixture_replay;
pub use auth::{AuthCommand, AuthLoginMethod, OAuthEncodingArgument, OAuthOverrideArgs};
pub use catalog::{CatalogCommand, VENDORED_MODEL_FACTS_PATH};

/// Top-level command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "pooler", version, about = "Composable AI protocol runtime")]
pub struct Cli {
    /// Configuration file to load.
    #[arg(short, long, global = true, default_value = "pooler.yaml")]
    pub config: PathBuf,
    /// Owner-private SQLite credential store. If omitted, use the platform
    /// state directory or `POOLER_CREDENTIAL_STORE`.
    #[arg(long, global = true)]
    pub credential_store: Option<PathBuf>,
    /// Secret reference used to derive the encrypted credential-store key.
    /// Literal values are rejected; use env:, file:, or keyring:.
    #[arg(long, global = true)]
    pub credential_key_ref: Option<String>,
    /// Poll the root configuration and imported files for debounced changes
    /// while serving. SIGHUP always performs an immediate reload on Unix.
    #[arg(long, global = true)]
    pub watch: bool,
    /// Operation to perform.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Parse and validate the configuration.
    Check,
    /// Print the validated configuration without resolving secrets.
    Config {
        /// Configuration operation.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// List compiled routes in match order.
    Routes,
    /// Start the proxy runtime.
    Serve,
    /// Run local diagnostics.
    Doctor,
    /// List configured public models.
    Models {
        /// Emit merged targets, source policy, and provenance as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Maintain the vendored per-model request-facts snapshot.
    Catalog {
        /// Catalog data operation.
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// List providers this build ships an endpoint for.
    Providers {
        /// Restrict output to providers whose ID or name contains this text.
        #[arg(long)]
        search: Option<String>,
        /// Emit the provider table as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect and replay sanitized compatibility fixtures.
    Fixture {
        /// Fixture operation.
        #[command(subcommand)]
        command: FixtureCommand,
    },
    /// Manage provider credentials.
    Auth {
        /// Credential-management operation.
        #[command(subcommand)]
        command: AuthCommand,
    },
}

/// Compatibility-fixture operations.
#[derive(Debug, Subcommand)]
pub enum FixtureCommand {
    /// Replay one fixture or every JSON fixture under a directory.
    Replay {
        /// Fixture file or directory to replay.
        path: PathBuf,
        /// Optional fixture file or directory containing the expected actual
        /// records.  Directory entries are paired by relative path.
        #[arg(long)]
        actual: Option<PathBuf>,
    },
    /// Capture a fixture into an owner-private sanitized record.
    Capture {
        /// Structured Pooler fixture to capture.
        input: PathBuf,
        /// Explicit output path for the owner-private capture.
        output: PathBuf,
        /// Retain bounded, recursively redacted JSON bodies.
        #[arg(long)]
        include_bodies: bool,
        /// Maximum body size retained when `--include-bodies` is set.
        #[arg(long, default_value_t = pooler_testkit::DEFAULT_MAX_CAPTURE_BODY_BYTES)]
        max_body_bytes: usize,
    },
    /// Render the versioned compatibility manifest as a release report.
    Report {
        /// Versioned manifest to render.
        #[arg(long, default_value = "fixtures/compatibility/manifest.json")]
        manifest: PathBuf,
        /// Report format.
        #[arg(long, value_enum, default_value_t = FixtureReportFormat::Markdown)]
        format: FixtureReportFormat,
        /// Write the report to a file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Formats accepted by [`FixtureCommand::Report`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum FixtureReportFormat {
    /// Human-readable Markdown matrix.
    Markdown,
    /// Validated manifest JSON with stable pretty-printing.
    Json,
}

/// Configuration inspection operations.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the source after validating it.
    Render,
    /// Print the deterministic source-configuration JSON Schema.
    Schema {
        /// Write the schema to a file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Runs one CLI command.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Check => {
            load(&cli.config)?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Config {
            command: ConfigCommand::Render,
        } => {
            let rendered = pooler_config::render_path(&cli.config)?;
            Config::from_yaml(cli.config.display().to_string(), &rendered)?.compile()?;
            print!("{rendered}");
            Ok(())
        }
        Command::Config {
            command: ConfigCommand::Schema { output },
        } => {
            let rendered = pooler_config::render_config_schema();
            if let Some(path) = output {
                std::fs::write(&path, rendered.as_bytes()).with_context(|| {
                    format!("could not write config schema `{}`", path.display())
                })?;
            } else {
                print!("{rendered}");
            }
            Ok(())
        }
        Command::Routes => {
            let config = load(&cli.config)?;
            for route in config.routes() {
                println!("{}", route.id());
            }
            Ok(())
        }
        Command::Serve => serve(
            &cli.config,
            cli.credential_store.as_deref(),
            cli.credential_key_ref.as_deref(),
            cli.watch,
        ),
        Command::Doctor => doctor::run(
            &cli.config,
            cli.credential_store.as_deref(),
            cli.credential_key_ref.as_deref(),
        ),
        Command::Models { json } => models(
            &cli.config,
            cli.credential_store.as_deref(),
            cli.credential_key_ref.as_deref(),
            json,
        ),
        Command::Catalog { command } => catalog::run(command),
        Command::Providers { search, json } => catalog::providers(search.as_deref(), json),
        Command::Fixture { command } => fixture_replay::run(command),
        Command::Auth { command } => auth::run(
            command,
            &cli.config,
            cli.credential_store.as_deref(),
            cli.credential_key_ref.as_deref(),
        ),
    }
}

fn fixture_report(
    manifest_path: &std::path::Path,
    format: FixtureReportFormat,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    let manifest = pooler_testkit::load_compatibility_manifest(manifest_path)?;
    let report = match format {
        FixtureReportFormat::Markdown => pooler_testkit::render_compatibility_matrix(&manifest),
        FixtureReportFormat::Json => serde_json::to_string_pretty(&manifest)
            .context("could not serialize compatibility manifest")?,
    };
    if let Some(path) = output_path {
        std::fs::write(path, report.as_bytes())
            .with_context(|| format!("could not write fixture report `{}`", path.display()))?;
    } else {
        print!("{report}");
    }
    Ok(())
}

fn load(path: &PathBuf) -> Result<pooler_config::CompiledConfig> {
    Config::from_path(path)?.compile().map_err(Into::into)
}

fn models(
    path: &PathBuf,
    explicit_store_path: Option<&std::path::Path>,
    credential_key_ref: Option<&str>,
    json: bool,
) -> Result<()> {
    let config = load(path)?;
    let catalog = if config.catalog().is_some() {
        let resources = runtime_resources(&config, explicit_store_path, credential_key_ref)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to initialize the model-discovery runtime")?;
        let catalog = pooler_server::CatalogRuntime::from_config(&config, resources.native)?;
        if let Some(catalog) = &catalog {
            runtime
                .block_on(catalog.refresh())
                .context("model catalog refresh failed")?;
        }
        catalog
    } else {
        None
    };
    if json {
        let view = pooler_server::merged_model_catalog_value(&config, catalog.as_deref());
        println!(
            "{}",
            serde_json::to_string_pretty(&view).context("could not serialize model catalog")?
        );
    } else {
        for model in pooler_server::merged_model_ids(&config, catalog.as_deref()) {
            println!("{model}");
        }
    }
    Ok(())
}

fn serve(
    path: &PathBuf,
    explicit_store_path: Option<&std::path::Path>,
    credential_key_ref: Option<&str>,
    watch: bool,
) -> Result<()> {
    let watcher = ConfigWatcher::new(path)?;
    let config = watcher.active().compile()?;
    let resources = runtime_resources(&config, explicit_store_path, credential_key_ref)?;
    pooler_observe::init_tracing().context("failed to initialize structured logging")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize the async runtime")?;
    runtime.block_on(async move {
        let server = pooler_server::HttpProxyServer::bind_with_native_runtime_and_pooling(
            config,
            resources.native,
            resources.pooling,
        )
        .await?;
        for listener in server.listener_addresses() {
            tracing::info!(
                listener = listener.id(),
                address = listener.address(),
                "listener bound"
            );
        }
        if let Some(address) = server.management_address() {
            tracing::info!(address, "management listener bound");
        }

        let runner = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        let watcher = Arc::new(Mutex::new(watcher));
        let reload_runner = {
            let server = server.clone();
            let watcher = Arc::clone(&watcher);
            tokio::spawn(async move { reload_loop(server, watcher, watch).await })
        };
        tokio::pin!(runner);
        tokio::select! {
            result = &mut runner => {
                reload_runner.abort();
                result
                    .context("HTTP proxy task panicked")?
                    .map_err(anyhow::Error::from)
            }
            signal = shutdown_signal() => {
                signal?;
                server
                    .drain(Duration::from_secs(30))
                    .await
                    .map_err(anyhow::Error::from)?;
                runner
                    .await
                    .context("HTTP proxy task panicked")?
                    .map_err(anyhow::Error::from)?;
                reload_runner
                    .await
                    .context("configuration reload task panicked")?
            }
        }
    })
}

async fn reload_loop(
    server: pooler_server::HttpProxyServer,
    watcher: Arc<Mutex<ConfigWatcher>>,
    watch: bool,
) -> Result<()> {
    let mut interval = tokio::time::interval(pooler_config::DEFAULT_RELOAD_POLL_INTERVAL);
    let cancellation = server.cancellation_token();
    #[cfg(unix)]
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("failed to install SIGHUP handler")?;

    loop {
        #[cfg(unix)]
        let event = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = interval.tick(), if watch => ReloadTrigger::Watch,
            signal = hup.recv() => {
                signal.context("SIGHUP handler failed")?;
                ReloadTrigger::Manual
            }
        };
        #[cfg(not(unix))]
        let event = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = interval.tick(), if watch => ReloadTrigger::Watch,
        };

        let candidate = {
            let watcher = Arc::clone(&watcher);
            let polled = tokio::task::spawn_blocking(move || {
                let mut watcher = watcher.lock().expect("configuration watcher lock poisoned");
                match event {
                    ReloadTrigger::Watch => watcher.poll().map_err(anyhow::Error::from),
                    ReloadTrigger::Manual => watcher
                        .force_candidate()
                        .map(Some)
                        .map_err(anyhow::Error::from),
                }
            })
            .await
            .context("configuration watcher task panicked")?;
            match polled {
                Ok(candidate) => candidate,
                Err(error) => {
                    tracing::warn!(error = %error, "configuration reload source rejected");
                    continue;
                }
            }
        };
        let Some(candidate) = candidate else {
            continue;
        };
        apply_reload_candidate(&server, &watcher, candidate).await?;
    }
}

#[derive(Clone, Copy, Debug)]
enum ReloadTrigger {
    Watch,
    Manual,
}

async fn apply_reload_candidate(
    server: &pooler_server::HttpProxyServer,
    watcher: &Arc<Mutex<ConfigWatcher>>,
    candidate: ConfigCandidate,
) -> Result<()> {
    let for_compile = candidate.clone();
    let compiled = tokio::task::spawn_blocking(move || for_compile.compile_with_generation(1))
        .await
        .context("configuration compiler task panicked")?;
    let compiled = match compiled {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "configuration reload rejected");
            return Ok(());
        }
    };
    match server.reload(compiled).await {
        Ok(outcome) => {
            tracing::info!(
                generation = outcome.generation(),
                changed = outcome.changed(),
                "configuration reload applied"
            );
            watcher
                .lock()
                .expect("configuration watcher lock poisoned")
                .accept(candidate);
        }
        Err(error) => {
            tracing::warn!(error = %error, "configuration reload rejected");
        }
    }
    Ok(())
}

struct RuntimeResources {
    native: Arc<NativeRuntime>,
    pooling: Arc<PoolingCoordinator>,
}

fn runtime_resources(
    config: &pooler_config::CompiledConfig,
    explicit_store_path: Option<&std::path::Path>,
    credential_key_ref: Option<&str>,
) -> Result<RuntimeResources> {
    let has_codex = config.upstreams().values().any(|upstream| {
        upstream
            .native()
            .is_some_and(|native| native.kind().eq_ignore_ascii_case("codex"))
    });
    if explicit_store_path.is_none() && !has_codex {
        return Ok(RuntimeResources {
            native: Arc::new(NativeRuntime::disabled()),
            pooling: Arc::new(PoolingCoordinator::new(config)?),
        });
    }
    let store_path = auth::credential_store_path(explicit_store_path)?;
    let master_key = auth::load_master_key(credential_key_ref).context(
        "credential-store persistence requires --credential-key-ref (use env:, file:, or keyring:)",
    )?;
    let store = SqliteStore::open_encrypted(store_path, master_key)
        .context("could not open encrypted credential store")?;
    let pooling = Arc::new(PoolingCoordinator::with_store(
        config,
        Arc::new(store.clone()),
    )?);
    let native = if has_codex {
        let token_store = Arc::new(SqliteOAuthTokenStore::new(store));
        Arc::new(NativeRuntime::new_with_sqlite(config, token_store)?)
    } else {
        Arc::new(NativeRuntime::disabled())
    };
    Ok(RuntimeResources { native, pooling })
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to wait for Ctrl-C")?;
        }
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to wait for Ctrl-C")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_shape_accepts_check() {
        let cli = Cli::try_parse_from(["pooler", "--config", "example.yaml", "check"])
            .expect("command should parse");
        assert!(matches!(cli.command, Command::Check));
        assert_eq!(cli.config, PathBuf::from("example.yaml"));
    }

    #[test]
    fn config_schema_command_accepts_an_output_path() {
        let cli = Cli::try_parse_from(["pooler", "config", "schema", "--output", "schema.json"])
            .expect("schema command should parse");
        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Schema { output: Some(path) }
            } if path == PathBuf::from("schema.json")
        ));
    }

    #[test]
    fn serve_command_is_available() {
        let cli = Cli::try_parse_from(["pooler", "serve"]).expect("command should parse");
        let error = run(cli).expect_err("missing default config should be reported");
        assert!(error.to_string().contains("failed to read configuration"));
    }

    #[test]
    fn models_command_accepts_json_catalog_output() {
        let cli = Cli::try_parse_from(["pooler", "models", "--json"])
            .expect("models JSON command should parse");
        assert!(matches!(cli.command, Command::Models { json: true }));
    }

    #[test]
    fn explicit_credential_store_wires_pooling_persistence() {
        let directory = tempfile::tempdir().expect("temporary store directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("store directory permissions");
        }
        let key_path = directory.path().join("store-key");
        std::fs::write(&key_path, b"cli-pooling-test-key").expect("key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("key file permissions");
        }
        let store_path = directory.path().join("credentials.sqlite3");
        let config = pooler_config::compile_yaml(
            "cli-pooling.yaml",
            r#"
version: 1
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  account: {provider: local, secret: env:POOLER_TEST_ACCOUNT}
account_pools: {pool: {accounts: [account]}}
policies:
  pooled: {selection: {strategy: fill_first, account_pool: pool}}
routes:
  - id: pooled
    listen: local
    target: {provider: local, policy: pooled}
"#,
        )
        .expect("pooling config");
        let key_reference = format!("file:{}", key_path.display());
        let resources = runtime_resources(&config, Some(&store_path), Some(&key_reference))
            .expect("runtime resources");
        let states = resources
            .pooling
            .credential_states()
            .expect("credential states");
        assert!(states
            .iter()
            .any(|state| state.credential_id == "account" && state.enabled));
    }

    #[test]
    fn auth_login_command_requires_explicit_state_and_response_inputs() {
        let cli = Cli::try_parse_from([
            "pooler",
            "--credential-store",
            "/private/credentials.sqlite3",
            "auth",
            "login",
            "codex",
            "--state",
            "state-1",
            "--response",
            "http://localhost:1455/auth/callback?code=redacted&state=state-1",
        ])
        .expect("auth command should parse");
        assert_eq!(
            cli.credential_store,
            Some(PathBuf::from("/private/credentials.sqlite3"))
        );
        assert!(matches!(
            cli.command,
            Command::Auth {
                command: AuthCommand::Login { .. }
            }
        ));
    }

    #[test]
    fn auth_status_and_revoke_commands_are_available() {
        let status = Cli::try_parse_from(["pooler", "auth", "status", "codex"])
            .expect("status command should parse");
        assert!(matches!(
            status.command,
            Command::Auth {
                command: AuthCommand::Status { provider: Some(_) }
            }
        ));
        let revoke = Cli::try_parse_from(["pooler", "auth", "revoke", "codex"])
            .expect("revoke command should parse");
        assert!(matches!(
            revoke.command,
            Command::Auth {
                command: AuthCommand::Revoke { .. }
            }
        ));
    }

    #[test]
    fn auth_provider_profiles_and_explicit_overrides_are_available() {
        let providers = Cli::try_parse_from(["pooler", "auth", "providers", "gemini"])
            .expect("provider support command should parse");
        assert!(matches!(
            providers.command,
            Command::Auth {
                command: AuthCommand::Providers {
                    profile: Some(profile)
                }
            } if profile == "gemini"
        ));

        let login = Cli::try_parse_from([
            "pooler",
            "auth",
            "login",
            "work-google",
            "--profile",
            "gemini",
            "--method",
            "device-code",
            "--client-id",
            "registered-client",
            "--scope",
            "scope-one",
            "--device-authorization-endpoint",
            "https://oauth2.googleapis.com/device/code",
        ])
        .expect("profiled login command should parse");
        assert!(matches!(
            login.command,
            Command::Auth {
                command: AuthCommand::Login {
                    profile: Some(profile),
                    method: AuthLoginMethod::DeviceCode,
                    ..
                }
            } if profile == "gemini"
        ));
    }

    #[test]
    fn fixture_report_command_defaults_to_markdown_manifest() {
        let cli = Cli::try_parse_from(["pooler", "fixture", "report"])
            .expect("fixture report should parse");
        assert!(matches!(
            cli.command,
            Command::Fixture {
                command: FixtureCommand::Report {
                    format: FixtureReportFormat::Markdown,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fixture_report_writes_the_generated_matrix() {
        let directory = tempfile::tempdir().expect("temporary report directory");
        let output = directory.path().join("matrix.md");
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/compatibility/manifest.json");

        fixture_report(&manifest, FixtureReportFormat::Markdown, Some(&output))
            .expect("manifest report");

        let expected_path = manifest
            .parent()
            .expect("manifest parent")
            .join("MATRIX.md");
        let expected = std::fs::read_to_string(expected_path).expect("checked-in matrix");
        let generated = std::fs::read_to_string(output).expect("report output");
        assert_eq!(generated, expected);
    }

    #[test]
    fn fixture_replay_command_accepts_a_path_without_server_options() {
        let cli = Cli::try_parse_from(["pooler", "fixture", "replay", "fixtures"])
            .expect("fixture replay should parse");
        assert!(matches!(
            cli.command,
            Command::Fixture {
                command: FixtureCommand::Replay { path, actual: None }
            } if path == PathBuf::from("fixtures")
        ));
    }

    #[test]
    fn fixture_capture_requires_an_explicit_output_path() {
        let cli = Cli::try_parse_from([
            "pooler",
            "fixture",
            "capture",
            "input.json",
            "capture.json",
            "--include-bodies",
            "--max-body-bytes",
            "1024",
        ])
        .expect("fixture capture should parse");
        assert!(matches!(
            cli.command,
            Command::Fixture {
                command: FixtureCommand::Capture {
                    input,
                    output,
                    include_bodies: true,
                    max_body_bytes: 1024,
                }
            } if input == PathBuf::from("input.json") && output == PathBuf::from("capture.json")
        ));
    }
}
