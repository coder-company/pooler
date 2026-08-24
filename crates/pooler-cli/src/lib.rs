//! Pooler's command-line interface.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pooler_auth::MemoryOAuthTokenStore;
use pooler_config::{Config, ConfigCandidate, ConfigWatcher};
use pooler_http::{NativeRuntime, PoolingCoordinator};
use pooler_store::{SqliteOAuthTokenStore, SqliteStore};

mod auth;
mod bootstrap;
mod catalog;
mod config_path;
mod config_recovery;
mod dashboard;
mod doctor;
mod fixture_replay;
mod migrate;
mod preflight;
mod tui;
pub use auth::{AuthCommand, AuthLoginMethod, OAuthEncodingArgument, OAuthOverrideArgs};
pub use catalog::{CatalogCommand, VENDORED_MODEL_FACTS_PATH};

/// Top-level command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "pooler", version, about = "Composable AI protocol runtime")]
pub struct Cli {
    /// Configuration file to load.
    ///
    /// When omitted, Pooler uses an existing `./pooler.yaml`; otherwise it
    /// discovers the platform configuration path (normally
    /// `$XDG_CONFIG_HOME/pooler/pooler.yaml` or `~/.config/pooler/pooler.yaml`).
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
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
    /// Create a compiler-validated owner-private starter deployment.
    Init {
        /// New directory to create. Existing paths are never modified.
        #[arg(long, default_value = "pooler-starter")]
        output: PathBuf,
        /// Emit the redacted bootstrap report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open a thin terminal view backed entirely by the management API.
    Tui {
        /// Management listener origin. Cleartext is accepted only on loopback.
        #[arg(long, default_value = "http://127.0.0.1:18477")]
        endpoint: String,
        /// Bearer token reference: env:, owner-private file:, or keyring:.
        #[arg(long)]
        token_ref: String,
        /// Render one snapshot and exit.
        #[arg(long)]
        once: bool,
        /// Refresh interval for the live view.
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,
    },
    /// Open or print the authenticated management dashboard URL.
    Dashboard {
        /// Explicit trusted remote dashboard URL. Local URLs are derived from configuration.
        #[arg(long)]
        url: Option<String>,
        /// Print the URL without invoking the platform browser opener.
        #[arg(long)]
        no_open: bool,
    },
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
    /// Probe DNS, TLS, authentication, discovery, endpoint reachability, and quota support without inference.
    Preflight,
    /// List configured public models.
    Models {
        /// Emit merged targets, source policy, and provenance as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print every configured listener and management endpoint without using
    /// a named client/tool profile.
    EndpointInventory {
        /// Emit the inventory as JSON (the default output is also JSON for
        /// machine-readable scripting).
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
    /// Convert supported legacy configurations without retaining secret values.
    Migrate {
        /// Legacy configuration format.
        #[command(subcommand)]
        command: MigrateCommand,
    },
    /// Manage provider credentials.
    Auth {
        /// Credential-management operation.
        #[command(subcommand)]
        command: AuthCommand,
    },
}

/// Legacy configuration migration operations.
#[derive(Debug, Subcommand)]
pub enum MigrateCommand {
    /// Translate the pinned CLIProxyAPI Plus configuration shape.
    Cliproxy {
        /// CLIProxyAPI YAML configuration to inspect.
        input: PathBuf,
        /// Report the redacted proposal without writing any file.
        #[arg(long)]
        dry_run: bool,
        /// New owner-private Pooler configuration path for a non-dry migration.
        #[arg(long)]
        output: Option<PathBuf>,
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
    /// Inspect and safely recover a blocked managed-configuration transaction.
    Recovery {
        /// Recovery operation.
        #[command(subcommand)]
        command: config_recovery::ConfigRecoveryCommand,
    },
}

/// Runs one CLI command.
pub fn run(cli: Cli) -> Result<()> {
    let Cli {
        config,
        credential_store,
        credential_key_ref,
        watch,
        command,
    } = cli;
    match command {
        Command::Init { output, json } => {
            let report = bootstrap::init(&output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Created private Pooler starter at {}",
                    report.directory.display()
                );
                println!("Configuration: {}", report.config.display());
                println!("Dashboard: {}", report.management_url);
                println!("Credential-store key: {}", report.credential_key_ref);
                for step in report.next_steps {
                    println!("- {step}");
                }
            }
            Ok(())
        }
        Command::Tui {
            endpoint,
            token_ref,
            once,
            interval_secs,
        } => tui::run(&endpoint, &token_ref, once, interval_secs),
        Command::Dashboard { url, no_open } => {
            let config = config_path::resolve(config.as_deref())?;
            dashboard::launch(&config, url.as_deref(), no_open)
        }
        Command::Check => {
            let config = config_path::resolve(config.as_deref())?;
            load(&config)?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Config {
            command: ConfigCommand::Render,
        } => {
            let config = config_path::resolve(config.as_deref())?;
            let rendered = pooler_config::render_path(&config)?;
            Config::from_yaml(config.display().to_string(), &rendered)?.compile()?;
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
        Command::Config {
            command: ConfigCommand::Recovery { command },
        } => {
            let config = config_path::resolve(config.as_deref())?;
            config_recovery::run(&config, command)
        }
        Command::Routes => {
            let config_path = config_path::resolve(config.as_deref())?;
            let config = load(&config_path)?;
            for route in config.routes() {
                println!("{}", route.id());
            }
            Ok(())
        }
        Command::Serve => serve(
            &config_path::resolve(config.as_deref())?,
            credential_store.as_deref(),
            credential_key_ref.as_deref(),
            watch,
        ),
        Command::Doctor => doctor::run(
            &config_path::resolve(config.as_deref())?,
            credential_store.as_deref(),
            credential_key_ref.as_deref(),
        ),
        Command::Preflight => preflight::run(
            &config_path::resolve(config.as_deref())?,
            credential_store.as_deref(),
            credential_key_ref.as_deref(),
        ),
        Command::Models { json } => models(
            &config_path::resolve(config.as_deref())?,
            credential_store.as_deref(),
            credential_key_ref.as_deref(),
            json,
        ),
        Command::EndpointInventory { json: _ } => {
            let config = load(&config_path::resolve(config.as_deref())?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&pooler_server::endpoint_inventory(&config))?
            );
            Ok(())
        }
        Command::Catalog { command } => catalog::run(command),
        Command::Providers { search, json } => catalog::providers(search.as_deref(), json),
        Command::Fixture { command } => fixture_replay::run(command),
        Command::Migrate {
            command:
                MigrateCommand::Cliproxy {
                    input,
                    dry_run,
                    output,
                },
        } => migrate::cliproxy(&input, dry_run, output.as_deref()),
        Command::Auth { command } => auth::run(
            command,
            &config_path::resolve(config.as_deref())?,
            credential_store.as_deref(),
            credential_key_ref.as_deref(),
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

fn load(path: &Path) -> Result<pooler_config::CompiledConfig> {
    Config::from_path(path)?.compile().map_err(Into::into)
}

fn models(
    path: &Path,
    explicit_store_path: Option<&Path>,
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
    path: &Path,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
    watch: bool,
) -> Result<()> {
    let operator_config_source = path.to_path_buf();
    let config_source = pooler_server::managed_configuration_source(&operator_config_source)
        .context("failed to read configuration or select a safe managed source")?;
    let watcher = ConfigWatcher::new(&config_source)?;
    let config = watcher.active().compile()?;
    let resources = runtime_resources(&config, explicit_store_path, credential_key_ref)?;
    pooler_observe::init_tracing().context("failed to initialize structured logging")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize the async runtime")?;
    runtime.block_on(async move {
        let server = match resources.management_store {
            Some(store) => {
                pooler_server::HttpProxyServer::bind_with_native_runtime_and_pooling_and_management_store(
                    config,
                    resources.native,
                    resources.pooling,
                    store,
                )
                .await?
            }
            None => {
                pooler_server::HttpProxyServer::bind_with_native_runtime_and_pooling(
                    config,
                    resources.native,
                    resources.pooling,
                )
                .await?
            }
        };
        if server.management_api().is_some() {
            server
                .enable_config_management(&operator_config_source)
                .context("failed to enable typed configuration management")?;
        }
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
        tokio::pin!(reload_runner);
        tokio::select! {
            result = &mut runner => {
                reload_runner.as_ref().get_ref().abort();
                result
                    .context("HTTP proxy task panicked")?
                    .map_err(anyhow::Error::from)
            }
            reload_result = &mut reload_runner => {
                let shutdown_requested = server.cancellation_token().is_cancelled();
                let reload_error = reload_task_error(reload_result, shutdown_requested);
                if let Some(error) = &reload_error {
                    tracing::error!(error = %error, "configuration reload task exited unexpectedly; shutting down");
                }
                server
                    .drain(Duration::from_secs(30))
                    .await
                    .context("failed to drain HTTP proxy after configuration reload task exit")?;
                runner
                    .await
                    .context("HTTP proxy task panicked")?
                    .map_err(anyhow::Error::from)?;
                match reload_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
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

fn reload_task_error(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    shutdown_requested: bool,
) -> Option<anyhow::Error> {
    match result {
        Ok(Ok(())) if shutdown_requested => None,
        Ok(Ok(())) => Some(anyhow!("configuration reload loop exited unexpectedly")),
        Ok(Err(error)) => Some(error.context("configuration reload loop failed")),
        Err(error) => {
            Some(anyhow::Error::from(error).context("configuration reload task panicked"))
        }
    }
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
            request = server.next_management_reload_request() => ReloadTrigger::Management {
                request_id: request.0,
                catalog_only: request.1,
                generation: request.2,
                source: request.3,
            },
        };
        #[cfg(not(unix))]
        let event = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = interval.tick(), if watch => ReloadTrigger::Watch,
            request = server.next_management_reload_request() => ReloadTrigger::Management {
                request_id: request.0,
                catalog_only: request.1,
                generation: request.2,
                source: request.3,
            },
        };

        let _unmanaged_reload_lease =
            if matches!(event, ReloadTrigger::Watch | ReloadTrigger::Manual) {
                if !server.try_begin_unmanaged_configuration_reload() {
                    tracing::info!("unmanaged reload deferred while a managed commit is pending");
                    continue;
                }
                Some(UnmanagedReloadLease(server.clone()))
            } else {
                None
            };

        let management_request = match event.clone() {
            ReloadTrigger::Management {
                request_id,
                catalog_only: true,
                generation,
                ..
            } => {
                match server.refresh_catalog(generation).await {
                    Ok(changed) => {
                        server.complete_management_reload(request_id, Some(changed), None);
                        tracing::info!(request_id, changed, "model catalog refresh completed");
                    }
                    Err(error) => {
                        server.complete_management_reload(request_id, None, None);
                        tracing::warn!(request_id, error = %error, "model catalog refresh failed");
                    }
                }
                continue;
            }
            ReloadTrigger::Management {
                request_id,
                catalog_only: false,
                generation,
                source,
            } => Some((request_id, generation, source.clone())),
            ReloadTrigger::Watch | ReloadTrigger::Manual => None,
        };
        let candidate = {
            let watcher = Arc::clone(&watcher);
            let candidate_event = event.clone();
            let polled = tokio::task::spawn_blocking(move || {
                let mut watcher = watcher.lock().expect("configuration watcher lock poisoned");
                match candidate_event {
                    ReloadTrigger::Watch => watcher.poll().map_err(anyhow::Error::from),
                    ReloadTrigger::Management {
                        source: Some(source),
                        ..
                    } => watcher
                        .force_candidate_from(source)
                        .map(Some)
                        .map_err(anyhow::Error::from),
                    ReloadTrigger::Manual | ReloadTrigger::Management { .. } => watcher
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
                    if let Some((request_id, _, _)) = &management_request {
                        server.complete_management_reload(*request_id, None, None);
                    }
                    tracing::warn!(error = %error, "configuration reload source rejected");
                    continue;
                }
            }
        };
        let Some(candidate) = candidate else {
            continue;
        };
        apply_reload_candidate(&server, &watcher, candidate, management_request).await?;
    }
}

struct UnmanagedReloadLease(pooler_server::HttpProxyServer);

impl Drop for UnmanagedReloadLease {
    fn drop(&mut self) {
        self.0.finish_unmanaged_configuration_reload();
    }
}

#[derive(Clone, Debug)]
enum ReloadTrigger {
    Watch,
    Manual,
    Management {
        request_id: u64,
        catalog_only: bool,
        generation: u64,
        source: Option<PathBuf>,
    },
}

async fn apply_reload_candidate(
    server: &pooler_server::HttpProxyServer,
    watcher: &Arc<Mutex<ConfigWatcher>>,
    candidate: ConfigCandidate,
    management_request: Option<(u64, u64, Option<PathBuf>)>,
) -> Result<()> {
    let for_compile = candidate.clone();
    let compiled = tokio::task::spawn_blocking(move || for_compile.compile_with_generation(1))
        .await
        .context("configuration compiler task panicked")?;
    let compiled = match compiled {
        Ok(config) => config,
        Err(error) => {
            if let Some((request_id, _, _)) = &management_request {
                server.complete_management_reload(*request_id, None, None);
            }
            tracing::warn!(error = %error, "configuration reload rejected");
            return Ok(());
        }
    };
    let reload = match &management_request {
        Some((_, generation, Some(source))) => {
            server
                .reload_staged_candidate(compiled, source, *generation)
                .await
        }
        Some((_, generation, None)) => server.reload_for_generation(compiled, *generation).await,
        None => server.reload(compiled).await,
    };
    match reload {
        Ok(outcome) => {
            if let Some((request_id, _, _)) = &management_request {
                server.complete_management_reload(
                    *request_id,
                    Some(outcome.changed()),
                    Some(server.config_generation()),
                );
            }
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
            if let Some((request_id, _, _)) = &management_request {
                server.complete_management_reload(*request_id, None, None);
            }
            tracing::warn!(error = %error, "configuration reload rejected");
        }
    }
    Ok(())
}

struct RuntimeResources {
    native: Arc<NativeRuntime>,
    pooling: Arc<PoolingCoordinator>,
    management_store: Option<Arc<SqliteStore>>,
}

fn runtime_resources(
    config: &pooler_config::CompiledConfig,
    explicit_store_path: Option<&std::path::Path>,
    credential_key_ref: Option<&str>,
) -> Result<RuntimeResources> {
    let has_native = config
        .upstreams()
        .values()
        .any(|upstream| upstream.native().is_some());
    let has_native_oauth = config.upstreams().values().any(|upstream| {
        upstream.native().is_some_and(|native| {
            upstream.oauth().is_some() || native.kind().eq_ignore_ascii_case("codex")
        })
    });
    let durable_management_requested = config.management().is_some();
    let persistence_requested = explicit_store_path.is_some()
        || credential_key_ref.is_some()
        || std::env::var_os("POOLER_CREDENTIAL_STORE").is_some();
    if !persistence_requested && !has_native_oauth && !durable_management_requested {
        let native = if has_native {
            NativeRuntime::new(config, Arc::new(MemoryOAuthTokenStore::new()))?
        } else {
            NativeRuntime::disabled()
        };
        return Ok(RuntimeResources {
            native: Arc::new(native),
            pooling: Arc::new(PoolingCoordinator::new(config)?),
            management_store: None,
        });
    }
    let store_path = auth::credential_store_path(explicit_store_path)?;
    let master_key = auth::load_master_key(credential_key_ref).context(
        "credential-store persistence requires --credential-key-ref (use env:, file:, or keyring:)",
    )?;
    let store = Arc::new(
        SqliteStore::open_encrypted(store_path, master_key)
            .context("could not open encrypted credential store")?,
    );
    let pooling = Arc::new(PoolingCoordinator::with_store(config, store.clone())?);
    let native = if has_native_oauth || durable_management_requested {
        let token_store = Arc::new(SqliteOAuthTokenStore::new((*store).clone()));
        Arc::new(NativeRuntime::new_with_sqlite(config, token_store)?)
    } else if has_native {
        Arc::new(NativeRuntime::new(
            config,
            Arc::new(MemoryOAuthTokenStore::new()),
        )?)
    } else {
        Arc::new(NativeRuntime::disabled())
    };
    Ok(RuntimeResources {
        native,
        pooling,
        management_store: Some(store),
    })
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
        assert_eq!(cli.config, Some(PathBuf::from("example.yaml")));
    }

    #[test]
    fn init_command_accepts_a_new_output_directory() {
        let cli = Cli::try_parse_from(["pooler", "init", "--output", "starter", "--json"])
            .expect("init command should parse");
        assert!(matches!(
            cli.command,
            Command::Init { output, json: true } if output == PathBuf::from("starter")
        ));
    }

    #[test]
    fn dashboard_command_can_print_without_opening_a_browser() {
        let cli = Cli::try_parse_from(["pooler", "dashboard", "--no-open"])
            .expect("dashboard command should parse");
        assert!(matches!(
            cli.command,
            Command::Dashboard {
                url: None,
                no_open: true
            }
        ));
    }

    #[test]
    fn tui_requires_a_secret_reference_and_supports_one_snapshot() {
        let cli = Cli::try_parse_from([
            "pooler",
            "tui",
            "--token-ref",
            "env:POOLER_MANAGEMENT_TOKEN",
            "--once",
        ])
        .expect("TUI command should parse");
        assert!(matches!(
            cli.command,
            Command::Tui {
                endpoint,
                token_ref,
                once: true,
                interval_secs: 5,
            } if endpoint == "http://127.0.0.1:18477"
                && token_ref == "env:POOLER_MANAGEMENT_TOKEN"
        ));
    }

    #[test]
    fn preflight_command_is_available() {
        let cli =
            Cli::try_parse_from(["pooler", "preflight"]).expect("preflight command should parse");
        assert!(matches!(cli.command, Command::Preflight));
    }

    #[test]
    fn cliproxy_migration_dry_run_is_available() {
        let cli =
            Cli::try_parse_from(["pooler", "migrate", "cliproxy", "legacy.yaml", "--dry-run"])
                .expect("migration command should parse");
        assert!(matches!(
            cli.command,
            Command::Migrate {
                command: MigrateCommand::Cliproxy {
                    input,
                    dry_run: true,
                    output: None
                }
            } if input == PathBuf::from("legacy.yaml")
        ));
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
    fn managed_config_recovery_commands_are_available() {
        for operation in ["status", "verify", "resume", "rollback", "abort"] {
            let cli = Cli::try_parse_from([
                "pooler",
                "--config",
                "pooler.yaml",
                "config",
                "recovery",
                operation,
                "--compact",
            ])
            .unwrap_or_else(|error| panic!("{operation} should parse: {error}"));
            assert!(matches!(
                cli.command,
                Command::Config {
                    command: ConfigCommand::Recovery { .. }
                }
            ));
        }
    }

    #[test]
    fn serve_command_is_available() {
        let directory = tempfile::tempdir().expect("temporary config directory");
        let missing = directory.path().join("missing/pooler.yaml");
        let cli = Cli::try_parse_from([
            "pooler",
            "--config",
            missing.to_str().expect("UTF-8 path"),
            "serve",
        ])
        .expect("command should parse");
        let error = run(cli).expect_err("missing explicit config should be reported");
        assert!(error.to_string().contains("failed to read configuration"));
    }

    #[test]
    fn models_command_accepts_json_catalog_output() {
        let cli = Cli::try_parse_from(["pooler", "models", "--json"])
            .expect("models JSON command should parse");
        assert!(matches!(cli.command, Command::Models { json: true }));
    }

    #[test]
    fn configured_native_runtime_does_not_require_a_credential_store() {
        let config = pooler_config::compile_yaml(
            "cli-configured-native.yaml",
            "version: 2\nupstreams:\n  xai:\n    url: http://127.0.0.1:1\n    native: {kind: xai}\n",
        )
        .expect("configured native config");

        let resources = runtime_resources(&config, None, None).expect("runtime resources");
        assert!(resources.native.supports(&config.upstreams()["xai"]));
    }

    #[test]
    fn explicit_credential_store_preserves_pooling_for_configured_native() {
        let directory = tempfile::tempdir().expect("temporary store directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("store directory permissions");
        }
        let key_path = directory.path().join("store-key");
        std::fs::write(&key_path, b"cli-configured-native-key").expect("key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("key file permissions");
        }
        let store_path = directory.path().join("credentials.sqlite3");
        let config = pooler_config::compile_yaml(
            "cli-configured-native-persistent.yaml",
            r#"
version: 2
upstreams:
  xai:
    url: http://127.0.0.1:1
    native: {kind: xai}
"#,
        )
        .expect("configured native config");
        let key_reference = format!("file:{}", key_path.display());
        let resources = runtime_resources(&config, Some(&store_path), Some(&key_reference))
            .expect("runtime resources");
        assert!(resources.native.supports(&config.upstreams()["xai"]));
        assert!(store_path.is_file());
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
version: 2
listeners: {local: {bind: 127.0.0.1:0}}
upstreams: {local: {url: http://127.0.0.1:1}}
accounts:
  account: {provider: local, secret: env:POOLER_TEST_ACCOUNT}
account_pools: {pool: {provider: local, accounts: [account]}}
policies:
  pooled: {selection: {strategy: fill_first}}
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

    #[test]
    fn reload_task_exit_is_clean_only_after_shutdown() {
        assert!(reload_task_error(Ok(Ok(())), true).is_none());

        let error = reload_task_error(Ok(Ok(())), false)
            .expect("reload task exit without shutdown should be reported");
        assert!(error
            .to_string()
            .contains("configuration reload loop exited unexpectedly"));
    }

    #[test]
    fn reload_task_error_is_preserved_for_shutdown_diagnostics() {
        let error = reload_task_error(Ok(Err(anyhow!("watcher failed"))), true)
            .expect("reload task errors should not be treated as clean shutdown");
        assert!(error
            .to_string()
            .contains("configuration reload loop failed"));
        assert!(format!("{error:#}").contains("watcher failed"));
    }

    #[tokio::test]
    async fn management_configuration_reload_is_applied_and_correlated() {
        const SECRET_ENV: &str = "POOLER_CLI_MANAGEMENT_RELOAD_TEST_KEY";
        std::env::set_var(SECRET_ENV, "cli-reload-secret");
        let directory = tempfile::tempdir().expect("temporary config directory");
        let path = directory.path().join("pooler.yaml");
        std::fs::write(
            &path,
            "version: 2\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_CLI_MANAGEMENT_RELOAD_TEST_KEY}}\nupstreams: {provider: {url: http://127.0.0.1:1}}\n",
        )
        .expect("initial config writes");
        let watcher = Arc::new(Mutex::new(
            ConfigWatcher::new(&path).expect("config watcher"),
        ));
        let config = watcher
            .lock()
            .expect("config watcher lock")
            .active()
            .compile()
            .expect("initial config compiles");
        let server = pooler_server::HttpProxyServer::bind(config)
            .await
            .expect("server binds");
        let api = server.management_api().expect("management api");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer cli-reload-secret"),
        );
        let accepted = api.handle(&http::Method::POST, "/reload", &headers);
        assert_eq!(accepted.status, http::StatusCode::ACCEPTED);
        let (request_id, catalog_only, generation, managed_source) =
            server.next_management_reload_request().await;
        assert!(managed_source.is_none());
        assert!(!catalog_only);
        assert_eq!(generation, 1);

        std::fs::write(
            &path,
            "version: 2\nmanagement: {bind: 127.0.0.1:0, auth: {secret: env:POOLER_CLI_MANAGEMENT_RELOAD_TEST_KEY}}\nupstreams: {provider: {url: http://127.0.0.1:2}}\n",
        )
        .expect("replacement config writes");
        let candidate = watcher
            .lock()
            .expect("config watcher lock")
            .force_candidate()
            .expect("candidate loads");
        apply_reload_candidate(
            &server,
            &watcher,
            candidate,
            Some((request_id, generation, None)),
        )
        .await
        .expect("management reload applies");
        assert_eq!(server.config_generation(), 2);

        let reloads = api.handle(&http::Method::GET, "/reloads", &headers);
        let reloads: serde_json::Value =
            serde_json::from_slice(&reloads.body).expect("reload history json");
        assert_eq!(reloads["reloads"][0]["status"], "succeeded");
        assert_eq!(
            reloads["reloads"][0]["accepted_configuration_generation"],
            1
        );
        assert_eq!(reloads["reloads"][0]["configuration_generation"], 2);
        server.begin_drain();
        std::env::remove_var(SECRET_ENV);
    }
}
