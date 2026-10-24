//! Read-only TLS feed server. Firewalls pull published snapshots; this
//! process never writes and has no approval API.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod snapshots;

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::Parser;
use ipnet::IpNet;
use mecfeedmcp_core::{FeedFormat, IndicatorKind, render_feed};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use snapshots::Loaded;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, PoisonError, RwLock},
    time::{SystemTime, UNIX_EPOCH},
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
    /// Last fully verified load. Readers only ever see a complete, verified set.
    cache: Arc<RwLock<Option<Arc<Loaded>>>>,
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
        cache: Arc::default(),
    };
    let router = router(app);

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

fn router(app: App) -> Router {
    Router::new()
        .route("/healthz", any(healthz))
        .route("/feeds/{format}/{kind}", any(feed))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(app)
}

fn parse_format(token: &str) -> Option<FeedFormat> {
    match token {
        "panos-edl" => Some(FeedFormat::PanosEdl),
        "junos-dynamic-address" => Some(FeedFormat::JunosDynamicAddress),
        "fortigate-threat-feed" => Some(FeedFormat::FortigateThreatFeed),
        "opnsense-url-table" => Some(FeedFormat::OpnsenseUrlTable),
        _ => None,
    }
}

fn parse_kind(token: &str) -> Option<IndicatorKind> {
    match token {
        "address" => Some(IndicatorKind::Ip),
        "prefix" => Some(IndicatorKind::Cidr),
        "domain" => Some(IndicatorKind::Domain),
        _ => None,
    }
}

/// Return the verified snapshot set for the current pointer, loading it on a change.
///
/// `Err` means fail closed: the pointer or the log could not be verified.
async fn verified(app: &App) -> Result<Arc<Loaded>> {
    let dir = app.snapshot_dir.clone();
    let current = tokio::task::spawn_blocking({
        let dir = dir.clone();
        move || snapshots::current_number(&dir)
    })
    .await
    .context("reading current panicked")??;
    let cached = app
        .cache
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(loaded) = cached.filter(|loaded| loaded.current == current) {
        return Ok(loaded);
    }
    let loaded = Arc::new(
        tokio::task::spawn_blocking(move || snapshots::load(&dir))
            .await
            .context("loading snapshots panicked")??,
    );
    *app.cache.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&loaded));
    Ok(loaded)
}

/// RFC 9110 section 13.1.2: `*` or any listed tag, weak comparison.
fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
        })
}

async fn feed(
    method: Method,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    State(app): State<App>,
    Path((format_token, kind_token)): Path<(String, String)>,
) -> Response {
    if !client_allowed(&app.allow, addr) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !matches!(method, Method::GET | Method::HEAD) {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, HeaderValue::from_static("GET, HEAD"))],
        )
            .into_response();
    }
    let (Some(format), Some(kind)) = (parse_format(&format_token), parse_kind(&kind_token)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !format.supports(kind) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let loaded = match verified(&app).await {
        Ok(loaded) => loaded,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "snapshot set does not verify");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let Some(latest) = loaded.versions.latest() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0);
    // render_feed rejects a document holding any expired entry and nothing
    // sweeps the log, so entries must expire on their own at serve time.
    let live: Vec<_> = latest
        .entries()
        .iter()
        .filter(|entry| entry.expires_at() > now)
        .cloned()
        .collect();
    let body = match render_feed(format, kind, &live, loaded.versions.policy(), now) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(%error, "feed does not render");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let digest = Sha256::digest(body.as_bytes());
    let hex = digest.iter().fold(String::new(), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    });
    let etag = format!("\"sha256-{hex}\"");
    let Ok(etag_value) = HeaderValue::from_str(&etag) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let cache_control = (header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if etag_matches(&headers, &etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag_value), cache_control],
        )
            .into_response();
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(body)
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (header::ETAG, etag_value),
            cache_control,
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{App, client_allowed, router};
    use axum::{
        body::{Body, to_bytes},
        extract::connect_info::MockConnectInfo,
        http::{Method, Request, StatusCode, header},
    };
    use ipnet::IpNet;
    use mecfeedmcp_core::{FeedVersions, IndicatorKind, Limits, Policy, Proposal, ProposedEntry};
    use sha2::{Digest, Sha256};
    use std::{
        net::{IpAddr, SocketAddr},
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    const DAY: i64 = 86_400;

    fn now() -> i64 {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch");
        i64::try_from(elapsed.as_secs()).expect("clock fits i64")
    }

    fn entry(kind: IndicatorKind, value: &str, seen: i64, expires_at: i64) -> ProposedEntry {
        ProposedEntry {
            kind,
            value: value.to_string(),
            source: "lab".to_string(),
            confidence: 50,
            first_seen: seen,
            last_seen: seen,
            expires_at: Some(expires_at),
            allow_broad_prefix: false,
        }
    }

    fn feed_versions() -> FeedVersions {
        let policy =
            Policy::try_new(vec![], vec![], Vec::<&str>::new(), Limits::default()).expect("policy");
        FeedVersions::open(policy)
    }

    /// Publish `entries` at `at` as the next version.
    fn publish(versions: &mut FeedVersions, at: i64, entries: Vec<ProposedEntry>) {
        versions
            .publish(&Proposal { entries }, at)
            .expect("publish");
    }

    /// Write every version and the `current` pointer, as `mecfeedmcp` does.
    fn write_layout(dir: &Path, versions: &FeedVersions, count: u64, current: u64) {
        for number in 1..=count {
            let version_dir = dir.join("versions").join(number.to_string());
            std::fs::create_dir_all(&version_dir).expect("version dir");
            let document = versions.document(number).expect("document");
            std::fs::write(
                version_dir.join("snapshot.json"),
                serde_json::to_vec(&document).expect("serialize"),
            )
            .expect("write snapshot");
        }
        std::fs::write(dir.join("current"), format!("{current}\n")).expect("write current");
    }

    fn one_version_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let at = now();
        let mut versions = feed_versions();
        publish(
            &mut versions,
            at,
            vec![
                entry(IndicatorKind::Ip, "1.0.0.1", at, at + DAY),
                entry(IndicatorKind::Ip, "1.0.0.2", at, at + DAY),
                entry(IndicatorKind::Domain, "bad.example.net", at, at + DAY),
            ],
        );
        write_layout(dir.path(), &versions, 1, 1);
        dir
    }

    fn app(dir: &Path) -> axum::Router {
        app_for_peer(dir, [127, 0, 0, 1])
    }

    fn app_for_peer(dir: &Path, peer: [u8; 4]) -> axum::Router {
        router(App {
            snapshot_dir: dir.to_path_buf(),
            allow: vec!["127.0.0.0/8".parse().expect("loopback")],
            cache: std::sync::Arc::default(),
        })
        .layer(MockConnectInfo(SocketAddr::from((peer, 1))))
    }

    async fn send(
        app: &axum::Router,
        method: Method,
        uri: &str,
        if_none_match: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(value) = if_none_match {
            request = request.header(header::IF_NONE_MATCH, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.expect("body");
        (parts.status, parts.headers, bytes.to_vec())
    }

    fn etag_of(body: &[u8]) -> String {
        let hex: String = Sha256::digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("\"sha256-{hex}\"")
    }

    #[tokio::test]
    async fn serves_rendered_feed_with_content_type_and_etag() {
        let dir = one_version_dir();
        let (status, headers, body) = send(
            &app(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"1.0.0.1\n1.0.0.2\n");
        assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            headers[header::ETAG].to_str().expect("etag"),
            etag_of(&body)
        );
    }

    #[tokio::test]
    async fn if_none_match_gives_304_only_on_a_match() {
        let dir = one_version_dir();
        let app = app(dir.path());
        let uri = "/feeds/panos-edl/address";
        let (_, headers, body) = send(&app, Method::GET, uri, None).await;
        let etag = etag_of(&body);
        assert_eq!(headers[header::ETAG].to_str().expect("etag"), etag);
        let weak = format!("\"other\", W/{etag}");
        for matching in [etag.as_str(), weak.as_str(), "*"] {
            let (status, headers, body) = send(&app, Method::GET, uri, Some(matching)).await;
            assert_eq!(status, StatusCode::NOT_MODIFIED, "{matching}");
            assert_eq!(headers[header::ETAG].to_str().expect("etag"), etag);
            assert!(body.is_empty());
        }
        let (status, _, body) = send(&app, Method::GET, uri, Some("\"sha256-nope\"")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn head_has_headers_and_no_body() {
        let dir = one_version_dir();
        let (status, headers, body) = send(
            &app(dir.path()),
            Method::HEAD,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key(header::ETAG));
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn new_current_version_is_served_with_a_new_etag() {
        let dir = one_version_dir();
        let app = app(dir.path());
        let uri = "/feeds/panos-edl/address";
        let (_, first, _) = send(&app, Method::GET, uri, None).await;
        let at = now();
        let mut versions = feed_versions();
        publish(
            &mut versions,
            at,
            vec![entry(IndicatorKind::Ip, "1.0.0.1", at, at + DAY)],
        );
        publish(
            &mut versions,
            at,
            vec![entry(IndicatorKind::Ip, "1.0.0.3", at, at + DAY)],
        );
        write_layout(dir.path(), &versions, 2, 2);
        let (status, second, body) = send(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.ends_with(b"1.0.0.3\n"), "{body:?}");
        assert_ne!(first[header::ETAG], second[header::ETAG]);
    }

    #[tokio::test]
    async fn tampered_snapshot_fails_closed() {
        let dir = one_version_dir();
        let path = dir.path().join("versions/1/snapshot.json");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("1.0.0.1"));
        std::fs::write(&path, text.replace("1.0.0.1", "1.0.0.9")).expect("tamper");
        let (status, _, body) = send(
            &app(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn stale_current_and_version_gaps_fail_closed() {
        let at = now();
        let mut versions = feed_versions();
        for value in ["1.0.0.1", "1.0.0.2", "1.0.0.3"] {
            publish(
                &mut versions,
                at,
                vec![entry(IndicatorKind::Ip, value, at, at + DAY)],
            );
        }
        let stale = tempfile::tempdir().expect("tempdir");
        write_layout(stale.path(), &versions, 3, 2);
        let gap = tempfile::tempdir().expect("tempdir");
        write_layout(gap.path(), &versions, 3, 3);
        std::fs::remove_dir_all(gap.path().join("versions/2")).expect("remove");
        for dir in [&stale, &gap] {
            let (status, _, body) = send(
                &app(dir.path()),
                Method::GET,
                "/feeds/panos-edl/address",
                None,
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn symlinked_snapshot_fails_closed() {
        let dir = one_version_dir();
        let real = dir.path().join("versions/1/snapshot.json");
        let moved = dir.path().join("elsewhere.json");
        std::fs::rename(&real, &moved).expect("move");
        std::os::unix::fs::symlink(&moved, &real).expect("symlink");
        let (status, _, _) = send(
            &app(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn empty_snapshot_dir_is_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (status, _, body) = send(
            &app(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn unknown_routes_and_unsupported_pairs_are_not_found() {
        let dir = one_version_dir();
        let app = app(dir.path());
        for uri in [
            "/feeds/junos-dynamic-address/domain",
            "/feeds/nope/address",
            "/feeds/panos-edl/nope",
            "/feeds/panos-edl",
            "/feeds",
            "/",
        ] {
            let (status, _, body) = send(&app, Method::GET, uri, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.is_empty(), "{uri}");
        }
    }

    #[tokio::test]
    async fn post_is_405_and_disallowed_peer_is_403() {
        let dir = one_version_dir();
        let uri = "/feeds/panos-edl/address";
        let (status, headers, _) = send(&app(dir.path()), Method::POST, uri, None).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[header::ALLOW], "GET, HEAD");
        let outsider = app_for_peer(dir.path(), [8, 8, 8, 8]);
        let (status, _, _) = send(&outsider, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn expired_entries_are_omitted_but_live_ones_are_served() {
        let dir = tempfile::tempdir().expect("tempdir");
        let at = now() - 10 * DAY;
        let mut versions = feed_versions();
        publish(
            &mut versions,
            at,
            vec![
                entry(IndicatorKind::Ip, "1.0.0.1", at, at + DAY),
                entry(IndicatorKind::Ip, "1.0.0.2", at, at + 20 * DAY),
            ],
        );
        write_layout(dir.path(), &versions, 1, 1);
        let (status, _, body) = send(
            &app(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"1.0.0.2\n");
    }

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
