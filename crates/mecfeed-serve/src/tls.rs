//! rustls server configuration, with optional client-certificate verification,
//! and an acceptor that tags each request with its connection's client-cert fingerprint.

use anyhow::{Context, Result};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use rustls::{
    RootCertStore, ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

/// SHA-256 of the client's leaf certificate DER; `None` when it sent none.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerCert(pub(crate) Option<[u8; 32]>);

/// Build the server config. With `client_ca`, a client may present a
/// certificate, and one that does not chain to the CA fails the handshake.
///
/// # Errors
///
/// Returns an error when a file cannot be read or parsed, or the CA file holds no certificate.
pub(crate) fn server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca: Option<&Path>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("reading TLS cert {}", cert_path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing TLS cert {}", cert_path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("TLS cert file contained no certificates");
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("reading TLS key {}", key_path.display()))?;
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?;
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(path) => {
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(path)
                .with_context(|| format!("reading client CA {}", path.display()))?
            {
                roots
                    .add(cert.with_context(|| format!("parsing client CA {}", path.display()))?)
                    .with_context(|| format!("adding client CA {}", path.display()))?;
            }
            if roots.is_empty() {
                anyhow::bail!(
                    "client CA file {} contained no certificates",
                    path.display()
                );
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .allow_unauthenticated()
                .build()
                .context("building the client certificate verifier")?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder
        .with_single_cert(certs, key)
        .context("building rustls server config")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// axum-server's rustls acceptor, plus the peer fingerprint on every request.
#[derive(Clone)]
pub(crate) struct PeerCertAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertAcceptor {
    /// Wrap a rustls config.
    pub(crate) fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

impl<I, S> Accept<I, S> for PeerCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
    RustlsAcceptor: Accept<I, S, Stream = TlsStream<I>, Service = S>,
    <RustlsAcceptor as Accept<I, S>>::Future: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = WithPeerCert<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepting = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepting.await?;
            let fingerprint = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|leaf| Sha256::digest(leaf.as_ref()).into());
            Ok((
                stream,
                WithPeerCert {
                    inner: service,
                    peer: PeerCert(fingerprint),
                },
            ))
        })
    }
}

/// A per-connection service that inserts [`PeerCert`] into each request.
#[derive(Clone)]
pub(crate) struct WithPeerCert<S> {
    inner: S,
    peer: PeerCert,
}

impl<S, B> tower::Service<axum::http::Request<B>> for WithPeerCert<S>
where
    S: tower::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.peer);
        self.inner.call(request)
    }
}

#[cfg(test)]
mod tests {
    use super::server_config;
    use std::sync::Arc;

    #[test]
    fn server_config_requires_a_readable_client_ca() {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = (dir.path().join("tls.crt"), dir.path().join("tls.key"));
        std::fs::write(&cert_path, cert.pem()).expect("cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("key");
        let provider = || Arc::new(rustls::crypto::ring::default_provider());
        server_config(&cert_path, &key_path, None, provider()).expect("no client CA");
        let missing = dir.path().join("missing.pem");
        assert!(server_config(&cert_path, &key_path, Some(&missing), provider()).is_err());
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").expect("empty");
        assert!(server_config(&cert_path, &key_path, Some(&empty), provider()).is_err());
        server_config(&cert_path, &key_path, Some(&cert_path), provider()).expect("CA file");
    }
}
