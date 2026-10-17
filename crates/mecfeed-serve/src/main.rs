//! Read-only TLS feed server. Firewalls pull published snapshots; this
//! process never writes and has no approval API.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::Parser;
use ipnet::IpNet;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

/// Read-only feed HTTP server. TLS is required; there is no plaintext mode.
#[derive(Debug, Parser)]
#[command(name = "mecfeed-serve", version, about)]
struct Args {
    /// Bind address, host:port.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,

    /// PEM certificate chain (leaf first).
    #[arg(long)]
    tls_cert: PathBuf,

    /// PEM private key.
    #[arg(long)]
    tls_key: PathBuf,

    /// Directory of signed, versioned snapshots. May be empty.
    #[arg(long)]
    snapshot_dir: PathBuf,

    /// Client IP/CIDR allowlist. Repeatable. Empty means loopback only.
    #[arg(long = "allow-cidr")]
    allow_cidr: Vec<IpNet>,
}

#[derive(Clone)]
struct App {
    snapshot_dir: PathBuf,
    allow: Vec<IpNet>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if !args.snapshot_dir.is_dir() {
        anyhow::bail!(
            "snapshot directory {} is missing or not a directory",
            args.snapshot_dir.display()
        );
    }

    let provider = rustls::crypto::ring::default_provider();
    provider
        .clone()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring crypto provider"))?;

    let tls = load_tls(&args.tls_cert, &args.tls_key, Arc::new(provider))?;
    let allow = if args.allow_cidr.is_empty() {
        vec![
            "127.0.0.0/8"
                .parse()
                .map_err(|err| anyhow::anyhow!("loopback v4 prefix: {err}"))?,
            "::1/128"
                .parse()
                .map_err(|err| anyhow::anyhow!("loopback v6 prefix: {err}"))?,
        ]
    } else {
        args.allow_cidr
    };

    let app = App {
        snapshot_dir: args.snapshot_dir,
        allow,
    };
    let router = Router::new()
        .route("/healthz", any(healthz))
        .route("/feeds/{id}", any(feed))
        .with_state(app);

    tracing::info!(listen = %args.listen, "mecfeed-serve listening (TLS only)");
    axum_server::bind_rustls(
        args.listen,
        axum_server::tls_rustls::RustlsConfig::from_config(tls),
    )
    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .context("feed server exited")?;
    Ok(())
}

fn load_tls(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    provider: Arc<rustls::crypto::CryptoProvider>,
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
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn client_allowed(allow: &[IpNet], addr: SocketAddr) -> bool {
    let ip: IpAddr = addr.ip();
    allow.iter().any(|net| net.contains(&ip))
}

async fn healthz(
    method: Method,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(app): State<App>,
) -> Response {
    if !client_allowed(&app.allow, addr) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match method {
        Method::GET | Method::HEAD => StatusCode::OK.into_response(),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn feed(
    method: Method,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(app): State<App>,
    Path(_id): Path<String>,
) -> Response {
    if !client_allowed(&app.allow, addr) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match method {
        Method::GET | Method::HEAD => {
            // Snapshots are not published in this skeleton.
            let _ = app.snapshot_dir;
            (StatusCode::NOT_FOUND, Body::empty()).into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::client_allowed;
    use ipnet::IpNet;
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn loopback_is_allowed_by_default_prefix() {
        let allow: Vec<IpNet> = vec!["127.0.0.0/8".parse().expect("loopback prefix parses")];
        let addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 1);
        assert!(client_allowed(&allow, addr));
        let addr = SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 1);
        assert!(!client_allowed(&allow, addr));
    }

    #[test]
    fn crate_version_is_nonempty() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
        assert!(!mecfeedmcp_core::version().is_empty());
    }
}
