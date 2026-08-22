//! Bounded, non-inference deployment preflight checks.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use pooler_auth::{HyperOAuthTransport, OAuthHttpRequest, OAuthTransport, OAuthTransportError};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Passed,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize)]
struct PreflightCheck {
    category: &'static str,
    target: String,
    status: CheckStatus,
    detail: &'static str,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    schema_version: u32,
    inference_requests_sent: u32,
    checks: Vec<PreflightCheck>,
}

pub(crate) fn run(
    path: &Path,
    explicit_store_path: Option<&Path>,
    credential_key_ref: Option<&str>,
) -> Result<()> {
    let config = pooler_config::load_path(path)
        .and_then(|config| config.compile())
        .context("preflight configuration failed validation")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize preflight runtime")?;
    let mut checks = Vec::new();

    runtime.block_on(async {
        let transport = HyperOAuthTransport::new(64 * 1024)
            .context("could not initialize native-root TLS transport")?;
        for upstream in config.upstreams().values() {
            let target = upstream.id().to_owned();
            let url = upstream.url();
            let Some(host) = url.host_str() else {
                checks.push(check(
                    "dns",
                    target,
                    CheckStatus::Failed,
                    "URL has no DNS host",
                ));
                continue;
            };
            let port = url.port_or_known_default().unwrap_or(443);
            let dns = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host, port)),
            )
            .await;
            let dns_passed = match dns {
                Ok(Ok(mut addresses)) => addresses.next().is_some(),
                Ok(Err(_)) | Err(_) => false,
            };
            checks.push(check(
                "dns",
                target.clone(),
                if dns_passed {
                    CheckStatus::Passed
                } else {
                    CheckStatus::Failed
                },
                if dns_passed {
                    "host resolved"
                } else {
                    "host did not resolve within the bound"
                },
            ));
            if !dns_passed {
                checks.push(check(
                    "endpoint",
                    target.clone(),
                    CheckStatus::Failed,
                    "not reached because DNS failed",
                ));
                if url.scheme() == "https" {
                    checks.push(check(
                        "tls",
                        target,
                        CheckStatus::Failed,
                        "not reached because DNS failed",
                    ));
                }
                continue;
            }

            let cancellation = CancellationToken::new();
            let probe = tokio::time::timeout(
                Duration::from_secs(10),
                transport.send(OAuthHttpRequest::get(url.clone()), cancellation),
            )
            .await;
            let reached = matches!(
                probe,
                Ok(Ok(_)) | Ok(Err(OAuthTransportError::ResponseTooLarge))
            );
            checks.push(check(
                "endpoint",
                target.clone(),
                if reached {
                    CheckStatus::Passed
                } else {
                    CheckStatus::Failed
                },
                if reached {
                    "bounded non-inference request reached the endpoint"
                } else {
                    "bounded endpoint request failed"
                },
            ));
            checks.push(check(
                "tls",
                target,
                if url.scheme() == "https" && reached {
                    CheckStatus::Passed
                } else if url.scheme() == "https" {
                    CheckStatus::Failed
                } else {
                    CheckStatus::Unsupported
                },
                if url.scheme() == "https" && reached {
                    "native-root TLS handshake succeeded"
                } else if url.scheme() == "https" {
                    "native-root TLS handshake failed"
                } else {
                    "cleartext endpoint has no TLS handshake"
                },
            ));
        }

        if config.catalog().is_some() {
            let resources =
                super::runtime_resources(&config, explicit_store_path, credential_key_ref)?;
            let catalog = pooler_server::CatalogRuntime::from_config(&config, resources.native)?;
            let discovered = match catalog {
                Some(catalog) => catalog.refresh().await.is_ok(),
                None => false,
            };
            for category in ["authentication", "discovery"] {
                checks.push(check(
                    category,
                    "catalog".to_owned(),
                    if discovered {
                        CheckStatus::Passed
                    } else {
                        CheckStatus::Failed
                    },
                    if discovered {
                        "authenticated discovery completed"
                    } else {
                        "authenticated discovery failed"
                    },
                ));
            }
        } else {
            checks.push(check(
                "authentication",
                "catalog".to_owned(),
                CheckStatus::Unsupported,
                "no catalog authentication probe is configured",
            ));
            checks.push(check(
                "discovery",
                "catalog".to_owned(),
                CheckStatus::Unsupported,
                "model discovery is not configured",
            ));
        }
        checks.push(check(
            "quota",
            "providers".to_owned(),
            CheckStatus::Unsupported,
            "no standardized non-billable live quota endpoint is documented",
        ));
        Ok::<(), anyhow::Error>(())
    })?;

    let failed = checks
        .iter()
        .any(|item| matches!(item.status, CheckStatus::Failed));
    println!(
        "{}",
        serde_json::to_string_pretty(&PreflightReport {
            schema_version: 1,
            inference_requests_sent: 0,
            checks,
        })?
    );
    if failed {
        anyhow::bail!("one or more preflight checks failed");
    }
    Ok(())
}

fn check(
    category: &'static str,
    target: String,
    status: CheckStatus,
    detail: &'static str,
) -> PreflightCheck {
    PreflightCheck {
        category,
        target,
        status,
        detail,
    }
}
