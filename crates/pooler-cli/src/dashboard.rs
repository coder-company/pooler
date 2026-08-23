//! Safe dashboard URL resolution and optional browser launch.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use url::Url;

pub(crate) fn launch(config_path: &Path, explicit_url: Option<&str>, no_open: bool) -> Result<()> {
    let url = match explicit_url {
        Some(value) => validate_explicit_url(value)?,
        None => local_dashboard_url(config_path)?,
    };
    println!("Dashboard: {url}");
    println!("Enter the management bearer token in the dashboard; it is never placed in the URL.");
    if !no_open {
        open_browser(url.as_str())?;
    }
    Ok(())
}

fn local_dashboard_url(config_path: &Path) -> Result<Url> {
    let config = pooler_config::load_path(config_path)
        .and_then(|config| config.compile())
        .context("could not compile configuration for dashboard launch")?;
    let management = config
        .management()
        .ok_or_else(|| anyhow!("management is disabled in this configuration"))?;
    let address = management.bind().parse::<SocketAddr>().map_err(|_| {
        anyhow!("browser launch requires a TCP management bind; use `pooler tui` for a Unix socket")
    })?;
    if !address.ip().is_loopback() {
        return Err(anyhow!(
            "remote dashboard launch requires an explicit trusted HTTPS --url"
        ));
    }
    Url::parse(&format!("http://{address}/management/ui/"))
        .context("management bind could not be represented as a dashboard URL")
}

fn validate_explicit_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid dashboard URL")?;
    if url.scheme() != "https" || url.host_str().is_none() || url.username() != "" {
        return Err(anyhow!(
            "explicit dashboard URLs must be absolute HTTPS URLs without user information"
        ));
    }
    if url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!(
            "dashboard URLs cannot contain credentials, query strings, or fragments"
        ));
    }
    Ok(url)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", ""]);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = std::process::Command::new("xdg-open");

    let status = command
        .arg(url)
        .status()
        .context("could not start the platform browser opener")?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("platform browser opener exited unsuccessfully"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dashboard_url_rejects_bearer_material() {
        for value in [
            "http://127.0.0.1:18477/management/ui/",
            "https://token@example.com/management/ui/",
            "https://example.com/management/ui/?token=secret",
        ] {
            assert!(validate_explicit_url(value).is_err(), "accepted {value}");
        }
        assert!(validate_explicit_url("https://example.com/management/ui/").is_ok());
    }

    #[test]
    fn local_dashboard_url_uses_compiled_loopback_management_bind() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("pooler.yaml");
        std::fs::write(
            &path,
            "version: 2\nmanagement:\n  bind: 127.0.0.1:18477\n  auth:\n    secret: env:POOLER_MANAGEMENT_TOKEN\n",
        )
        .expect("config");
        assert_eq!(
            local_dashboard_url(&path).expect("URL").as_str(),
            "http://127.0.0.1:18477/management/ui/"
        );
    }
}
