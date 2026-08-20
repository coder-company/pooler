//! Inbound TLS listener setup and bounded handshakes.
//!
//! The configuration layer retains only paths and policy. This module opens
//! certificate material at bind time, verifies its ownership, and keeps the
//! resulting rustls configuration in memory for the lifetime of the listener.
//! Platforms without a handle-safe no-follow open primitive fail closed rather
//! than reopening a path after a symlink check.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::fs::OpenOptions;

use pooler_config::ListenerTlsPlan;
use ring::digest::{Context, SHA256};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use thiserror::Error;
use tokio::{net::TcpStream, time};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::sync::CancellationToken;

const MAX_CERTIFICATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const MAX_CLIENT_CA_BYTES: u64 = 4 * 1024 * 1024;

/// Errors raised while preparing an inbound TLS listener.
#[derive(Debug, Error)]
pub(crate) enum TlsError {
    /// The certificate/key/CA file could not be opened or read.
    #[error("could not read TLS {role} file `{path}`")]
    File {
        role: &'static str,
        path: String,
        #[source]
        source: io::Error,
    },
    /// The file is not a regular owner-private file.
    #[error("TLS {role} file `{path}` must be a regular owner-private file")]
    InsecureFile { role: &'static str, path: String },
    /// The platform does not provide the handle-safe checks required here.
    #[cfg(not(unix))]
    #[error("TLS {role} file `{path}` cannot be validated safely on this platform")]
    PlatformFileValidationUnavailable { role: &'static str, path: String },
    /// The PEM file did not contain the requested material.
    #[error("TLS {role} file `{path}` contains no usable PEM material")]
    InvalidPem { role: &'static str, path: String },
    /// The certificate/key pair could not be used to build a server identity.
    #[error("TLS certificate and private key could not be used together")]
    InvalidIdentity,
    /// The configured client CA bundle could not build a verifier.
    #[error("TLS client CA bundle could not build a certificate verifier")]
    InvalidClientVerifier,
    /// The handshake failed or exceeded its configured bound.
    #[error("TLS handshake failed")]
    Handshake,
    /// The listener was cancelled while a handshake was pending.
    #[error("TLS handshake cancelled")]
    Cancelled,
}

/// A prepared TLS acceptor and its per-connection handshake bound.
pub(crate) struct PreparedTls {
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
    fingerprint: [u8; 32],
}

impl PreparedTls {
    /// Load certificate material and build a TLS 1.2+ server configuration.
    pub(crate) fn load(plan: &ListenerTlsPlan) -> Result<Self, TlsError> {
        let certificate_bytes =
            read_owner_private_file(Path::new(plan.cert()), "certificate", MAX_CERTIFICATE_BYTES)?;
        let private_key_bytes =
            read_owner_private_file(Path::new(plan.key()), "private key", MAX_PRIVATE_KEY_BYTES)?;
        let certificate_chain = parse_certificates(&certificate_bytes, "certificate", plan.cert())?;
        let private_key = parse_private_key(&private_key_bytes, plan.key())?;
        let mut client_ca_bytes = None;

        let builder = ServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ]);
        let mut config = if let Some(client_auth) = plan.client_auth() {
            let ca_bytes = read_owner_private_file(
                Path::new(client_auth.ca()),
                "client CA",
                MAX_CLIENT_CA_BYTES,
            )?;
            client_ca_bytes = Some(ca_bytes.clone());
            let ca_chain = parse_certificates(&ca_bytes, "client CA", client_auth.ca())?;
            let mut roots = RootCertStore::empty();
            for certificate in ca_chain {
                roots
                    .add(certificate)
                    .map_err(|_| TlsError::InvalidClientVerifier)?;
            }
            if roots.is_empty() {
                return Err(TlsError::InvalidClientVerifier);
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = if client_auth.required() {
                verifier
                    .build()
                    .map_err(|_| TlsError::InvalidClientVerifier)?
            } else {
                verifier
                    .allow_unauthenticated()
                    .build()
                    .map_err(|_| TlsError::InvalidClientVerifier)?
            };
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificate_chain, private_key)
                .map_err(|_| TlsError::InvalidIdentity)?
        } else {
            builder
                .with_no_client_auth()
                .with_single_cert(certificate_chain, private_key)
                .map_err(|_| TlsError::InvalidIdentity)?
        };

        config.alpn_protocols = plan
            .alpn()
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
        let fingerprint = tls_fingerprint(
            plan,
            &certificate_bytes,
            &private_key_bytes,
            client_ca_bytes.as_deref(),
        );

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            handshake_timeout: plan.handshake_timeout(),
            fingerprint,
        })
    }

    pub(crate) const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Perform one bounded, cancellation-aware TLS handshake.
    pub(crate) async fn accept(
        &self,
        stream: TcpStream,
        cancellation: &CancellationToken,
    ) -> Result<Option<TlsStream<TcpStream>>, TlsError> {
        let handshake = self.acceptor.accept(stream);
        tokio::pin!(handshake);
        tokio::select! {
            _ = cancellation.cancelled() => Err(TlsError::Cancelled),
            result = time::timeout(self.handshake_timeout, &mut handshake) => {
                match result {
                    Ok(Ok(stream)) => Ok(Some(stream)),
                    Ok(Err(_)) | Err(_) => Err(TlsError::Handshake),
                }
            }
        }
    }
}

fn tls_fingerprint(
    plan: &ListenerTlsPlan,
    certificate: &[u8],
    private_key: &[u8],
    client_ca: Option<&[u8]>,
) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(b"pooler inbound tls v1\0");
    for value in [
        plan.cert().as_bytes(),
        plan.key().as_bytes(),
        certificate,
        private_key,
    ] {
        context.update(&(value.len() as u64).to_be_bytes());
        context.update(value);
    }
    context.update(&[u8::from(client_ca.is_some())]);
    if let Some(client_ca) = client_ca {
        context.update(&(client_ca.len() as u64).to_be_bytes());
        context.update(client_ca);
    }
    for protocol in plan.alpn() {
        context.update(&(protocol.len() as u64).to_be_bytes());
        context.update(protocol.as_bytes());
    }
    context.update(&plan.handshake_timeout().as_nanos().to_be_bytes());
    if let Some(client_auth) = plan.client_auth() {
        context.update(client_auth.ca().as_bytes());
        context.update(&[u8::from(client_auth.required())]);
    }
    let digest = context.finish();
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    fingerprint
}

fn parse_certificates(
    bytes: &[u8],
    role: &'static str,
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certificates = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidPem {
            role,
            path: path.to_owned(),
        })?;
    if certificates.is_empty() {
        return Err(TlsError::InvalidPem {
            role,
            path: path.to_owned(),
        });
    }
    Ok(certificates)
}

fn parse_private_key(bytes: &[u8], path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_slice(bytes).map_err(|_| TlsError::InvalidPem {
        role: "private key",
        path: path.to_owned(),
    })
}

fn read_owner_private_file(
    path: &Path,
    role: &'static str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, TlsError> {
    let file = open_owner_private_file(path, role)?;
    let metadata = file.metadata().map_err(|source| TlsError::File {
        role,
        path: path.display().to_string(),
        source,
    })?;
    if metadata.len() > maximum_bytes {
        return Err(TlsError::File {
            role,
            path: path.display().to_string(),
            source: io::Error::new(io::ErrorKind::InvalidData, "TLS file is too large"),
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| TlsError::File {
            role,
            path: path.display().to_string(),
            source,
        })?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(TlsError::File {
            role,
            path: path.display().to_string(),
            source: io::Error::new(io::ErrorKind::InvalidData, "TLS file is too large"),
        });
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_owner_private_file(path: &Path, role: &'static str) -> Result<File, TlsError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| TlsError::File {
            role,
            path: path.display().to_string(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| TlsError::File {
        role,
        path: path.display().to_string(),
        source,
    })?;
    let owner = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o400 == 0
    {
        return Err(TlsError::InsecureFile {
            role,
            path: path.display().to_string(),
        });
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_owner_private_file(path: &Path, role: &'static str) -> Result<File, TlsError> {
    Err(TlsError::PlatformFileValidationUnavailable {
        role,
        path: path.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn symlinked_or_group_readable_material_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.pem");
        std::fs::write(&target, b"test").expect("write target");
        let link = directory.path().join("link.pem");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        assert!(matches!(
            open_owner_private_file(&link, "certificate"),
            Err(TlsError::File { .. })
        ));

        let open = directory.path().join("open.pem");
        std::fs::write(&open, b"test").expect("write open file");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        assert!(matches!(
            open_owner_private_file(&open, "private key"),
            Err(TlsError::InsecureFile { .. })
        ));
    }

    #[cfg(not(unix))]
    #[test]
    fn unsupported_platform_fails_closed_before_reopen() {
        let error = open_owner_private_file(Path::new("certificate.pem"), "certificate")
            .expect_err("platform-safe validation is required");
        assert!(matches!(
            error,
            TlsError::PlatformFileValidationUnavailable { .. }
        ));
    }
}
