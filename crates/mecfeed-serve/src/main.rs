//! Read-only TLS feed server. Firewalls pull published snapshots; this
//! process never writes and has no approval API.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod clients;
mod snapshots;

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::Engine;
use clap::Parser;
use clients::{Clients, Denial};
use ipnet::IpNet;
use mecfeedmcp_core::{
    FeedFormat, IndicatorKind, Limits, Policy, PublicKey, TrustedKeys, render_feed,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, de::IgnoredAny};
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
    #[arg(long, required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"])]
    tls_cert: Option<PathBuf>,

    /// PEM private key.
    #[arg(long, required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"])]
    tls_key: Option<PathBuf>,

    /// Operator feed.json. Its prefix and domain allowlists are re-applied to
    /// every published version before it is verified and before each render.
    #[arg(long, required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"])]
    feed_config: Option<PathBuf>,

    /// Directory of versioned snapshots; the current one must carry a trusted signature. May be empty.
    #[arg(long, required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"])]
    snapshot_dir: Option<PathBuf>,

    /// Public key trusted to sign snapshots: a file holding one base64 Ed25519 key.
    /// Repeatable; at least one is required.
    #[arg(long = "trusted-snapshot-key", required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"])]
    trusted_snapshot_key: Vec<PathBuf>,

    /// Client IP/CIDR allowlist. Repeatable. Empty means loopback only.
    #[arg(long = "allow-cidr")]
    allow_cidr: Vec<IpNet>,

    /// Feed client list (JSON). Every feed request must come from a listed client.
    #[arg(
        long,
        conflicts_with = "allow_anonymous_feeds",
        required_unless_present_any = ["allow_anonymous_feeds", "generate_basic_password", "print_cert_fingerprint"]
    )]
    clients_file: Option<PathBuf>,

    /// Serve feeds to any client the CIDR allowlist admits, without client authentication.
    #[arg(long)]
    allow_anonymous_feeds: bool,

    /// PEM CA certificates that sign client certificates. Required when a client has `cert_sha256`.
    #[arg(long, value_name = "PEM", conflicts_with = "allow_anonymous_feeds")]
    client_ca: Option<PathBuf>,

    /// Print a new Basic password on stdout and its `basic_sha256` on stderr, then exit.
    #[arg(long, conflicts_with = "print_cert_fingerprint")]
    generate_basic_password: bool,

    /// Print the SHA-256 of the first certificate in a PEM file (for `cert_sha256`), then exit.
    #[arg(long, value_name = "PEM")]
    print_cert_fingerprint: Option<PathBuf>,
}

/// The slice of feed.json that serve needs. MCP-only keys are accepted but not
/// read; any other key is rejected so a typo cannot drop an allowlist. The
/// accepted key set mirrors `FeedConfig` in `crates/mecfeedmcp/src/config.rs` and
/// `FeedConfig::policy`; both must change together.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // MCP-only keys are typed IgnoredAny and never read.
struct FeedPolicyConfig {
    version: u32,
    #[serde(default)]
    tenant: IgnoredAny,
    #[serde(default)]
    changeset_state_file: IgnoredAny,
    #[serde(default)]
    snapshot_dir: IgnoredAny,
    #[serde(default)]
    approval_ttl_secs: IgnoredAny,
    #[serde(default)]
    misp: IgnoredAny,
    #[serde(default)]
    own_prefixes: Vec<String>,
    #[serde(default)]
    allow_cidrs: Vec<String>,
    #[serde(default)]
    allow_domain_suffixes: Vec<String>,
}

impl FeedPolicyConfig {
    fn policy(&self) -> Result<Policy> {
        if self.version != 1 {
            anyhow::bail!("feed config version must be 1");
        }
        let parse = |values: &[String]| -> Result<Vec<IpNet>> {
            values
                .iter()
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("feed config has an unparsable CIDR"))
                })
                .collect()
        };
        Policy::try_new(
            parse(&self.own_prefixes)?,
            parse(&self.allow_cidrs)?,
            self.allow_domain_suffixes.iter().map(String::as_str),
            Limits::default(),
        )
        .context("feed config policy is not acceptable")
    }
}

fn load_policy(path: &std::path::Path) -> Result<Policy> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading feed config {}", path.display()))?;
    let config: FeedPolicyConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing feed config {}", path.display()))?;
    config.policy()
}

/// Load every `--trusted-snapshot-key` file into one trust list.
///
/// # Errors
///
/// Returns an error when a file cannot be read or parsed, when none is given,
/// or when two files hold the same key.
fn load_trusted_keys(paths: &[PathBuf]) -> Result<TrustedKeys> {
    let keys = paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading trusted snapshot key {}", path.display()))?;
            PublicKey::from_base64(&text)
                .with_context(|| format!("parsing trusted snapshot key {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    TrustedKeys::new(keys).context("trusted snapshot keys are not acceptable")
}

#[derive(Clone)]
struct App {
    snapshot_dir: PathBuf,
    allow: Vec<IpNet>,
    policy: Policy,
    /// Keys the current snapshot's signature must verify against.
    trusted: TrustedKeys,
    /// Feed clients; `None` when `--allow-anonymous-feeds` was given.
    clients: Option<Arc<Clients>>,
    /// Serializes reloads so an older load can never overwrite a newer one.
    reload: Arc<tokio::sync::Mutex<()>>,
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
    let provider = rustls::crypto::ring::default_provider();
    if args.generate_basic_password {
        let (password, digest) = generate_basic_password(provider.secure_random)?;
        println!("{password}");
        eprintln!("basic_sha256: {digest}");
        return Ok(());
    }
    if let Some(path) = &args.print_cert_fingerprint {
        println!("{}", cert_fingerprint(path)?);
        return Ok(());
    }
    let (Some(tls_cert), Some(tls_key), Some(feed_config), Some(snapshot_dir)) = (
        args.tls_cert.clone(),
        args.tls_key.clone(),
        args.feed_config.clone(),
        args.snapshot_dir.clone(),
    ) else {
        anyhow::bail!("--tls-cert, --tls-key, --feed-config and --snapshot-dir are required");
    };
    if !snapshot_dir.is_dir() {
        anyhow::bail!(
            "snapshot directory {} is missing or not a directory",
            snapshot_dir.display()
        );
    }

    provider
        .clone()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring crypto provider"))?;

    let policy = load_policy(&feed_config)?;
    let trusted = load_trusted_keys(&args.trusted_snapshot_key)?;
    let clients = match &args.clients_file {
        Some(path) => Some(Arc::new(clients::load(path)?)),
        None => {
            tracing::warn!(
                "--allow-anonymous-feeds: feeds are served without client authentication"
            );
            None
        }
    };
    check_client_ca(clients.as_deref(), args.client_ca.as_deref())?;
    let tls = load_tls(&tls_cert, &tls_key, Arc::new(provider))?;
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
        snapshot_dir,
        allow,
        policy,
        trusted,
        clients,
        reload: Arc::default(),
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

/// Refuse certificate clients without a CA to verify their chains.
fn check_client_ca(clients: Option<&Clients>, client_ca: Option<&std::path::Path>) -> Result<()> {
    if clients.is_some_and(Clients::needs_client_ca) && client_ca.is_none() {
        anyhow::bail!("the client list has certificate clients; --client-ca is required");
    }
    Ok(())
}

/// A new Basic password (32 random bytes, base64url without padding) and its `basic_sha256`.
fn generate_basic_password(random: &dyn rustls::crypto::SecureRandom) -> Result<(String, String)> {
    let mut bytes = [0u8; 32];
    random
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("no secure random source"))?;
    let password = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let digest = hex(&Sha256::digest(password.as_bytes()));
    Ok((password, digest))
}

/// SHA-256 of the first certificate in a PEM file, as lowercase hex.
fn cert_fingerprint(path: &std::path::Path) -> Result<String> {
    let cert = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading certificate {}", path.display()))?
        .next()
        .with_context(|| format!("{} holds no certificate", path.display()))?
        .with_context(|| format!("parsing certificate {}", path.display()))?;
    Ok(hex(&Sha256::digest(cert.as_ref())))
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

async fn healthz(method: Method) -> Response {
    match method {
        Method::GET | Method::HEAD => StatusCode::OK.into_response(),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// Router-wide client allowlist: applies to every route, matched or not.
async fn require_allowed_client(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(app): State<App>,
    request: Request,
    next: Next,
) -> Response {
    if !client_allowed(&app.allow, addr) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// `WWW-Authenticate` value on every 401.
const BASIC_CHALLENGE: &str = "Basic realm=\"mecfeed\", charset=\"UTF-8\"";

/// Feed-route client authentication. Runs before the format and kind are parsed,
/// so an unauthenticated caller learns nothing about which feeds exist.
async fn require_client(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((format, kind)): Path<(String, String)>,
    request: Request,
    next: Next,
) -> Response {
    let Some(clients) = &app.clients else {
        return next.run(request).await;
    };
    let feed = format!("{format}/{kind}");
    match clients.authorize(None, request.headers().get(header::AUTHORIZATION), &feed) {
        Ok(_) => next.run(request).await,
        Err(denial) => {
            tracing::info!(
                client_ip = %addr.ip(),
                client = denial.client().unwrap_or(""),
                reason = denial.reason(),
                "feed request denied"
            );
            if matches!(denial, Denial::FeedNotAllowed { .. }) {
                StatusCode::FORBIDDEN.into_response()
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    [(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static(BASIC_CHALLENGE),
                    )],
                )
                    .into_response()
            }
        }
    }
}

fn router(app: App) -> Router {
    Router::new()
        .route("/feeds/{format}/{kind}", any(feed))
        // Only the feed route above is covered; routes added after it are not.
        .route_layer(middleware::from_fn_with_state(app.clone(), require_client))
        .route("/healthz", any(healthz))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(
            app.clone(),
            require_allowed_client,
        ))
        .with_state(app)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
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
    let _reload = app.reload.lock().await;
    let cached = app
        .cache
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(loaded) = cached.filter(|loaded| loaded.current == current) {
        return Ok(loaded);
    }
    let policy = app.policy.clone();
    let trusted = app.trusted.clone();
    let loaded = Arc::new(
        tokio::task::spawn_blocking(move || snapshots::load(&dir, policy, &trusted))
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
    State(app): State<App>,
    Path((format_token, kind_token)): Path<(String, String)>,
) -> Response {
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
    let Some(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
    else {
        tracing::error!("system clock is before the epoch or out of range");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
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
    let etag = format!("\"sha256-{}\"", hex(&digest));
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
    use super::{App, FeedPolicyConfig, client_allowed, hex, load_trusted_keys, router};
    use axum::{
        body::{Body, to_bytes},
        extract::connect_info::MockConnectInfo,
        http::{Method, Request, StatusCode, header},
    };
    use base64::prelude::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ipnet::IpNet;
    use mecfeedmcp_core::{
        FeedVersions, IndicatorKind, Limits, Policy, Proposal, ProposedEntry, PublicKey,
        TrustedKeys, encode_signature_file, signed_message,
    };
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

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_text(key: &SigningKey) -> String {
        BASE64_STANDARD.encode(key.verifying_key().as_bytes())
    }

    fn trusted(keys: &[&SigningKey]) -> TrustedKeys {
        TrustedKeys::new(
            keys.iter()
                .map(|key| PublicKey::from_base64(&public_text(key)).expect("public key"))
                .collect(),
        )
        .expect("trusted")
    }

    /// `snapshot.sig` bytes for `digest`, signed by `key`.
    fn signature_for(key: &SigningKey, digest: &str) -> Vec<u8> {
        let key_id = PublicKey::from_base64(&public_text(key))
            .expect("public key")
            .key_id()
            .to_string();
        let signature = key.sign(&signed_message(digest).expect("message"));
        encode_signature_file(&key_id, &BASE64_STANDARD.encode(signature.to_bytes()))
    }

    fn sig_path(dir: &Path, version: u64) -> std::path::PathBuf {
        dir.join(format!("versions/{version}/snapshot.sig"))
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
            std::fs::write(
                version_dir.join("snapshot.sig"),
                signature_for(&test_key(1), &document.digest),
            )
            .expect("write signature");
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
        app_with_policy(dir, peer, empty_policy())
    }

    fn empty_policy() -> Policy {
        Policy::try_new(vec![], vec![], Vec::<&str>::new(), Limits::default()).expect("policy")
    }

    fn app_with_policy(dir: &Path, peer: [u8; 4], policy: Policy) -> axum::Router {
        app_with(dir, peer, policy, trusted(&[&test_key(1)]))
    }

    fn app_with_trust(dir: &Path, keys: TrustedKeys) -> axum::Router {
        app_with(dir, [127, 0, 0, 1], empty_policy(), keys)
    }

    fn app_with(dir: &Path, peer: [u8; 4], policy: Policy, keys: TrustedKeys) -> axum::Router {
        router(App {
            snapshot_dir: dir.to_path_buf(),
            allow: vec!["127.0.0.0/8".parse().expect("loopback")],
            policy,
            trusted: keys,
            clients: None,
            reload: std::sync::Arc::default(),
            cache: std::sync::Arc::default(),
        })
        .layer(MockConnectInfo(SocketAddr::from((peer, 1))))
    }

    const PANOS_PASSWORD: &str = "s3cret-password";

    #[test]
    fn helpers_parse_without_serving_flags() {
        use clap::Parser;
        assert!(
            super::Args::try_parse_from(["mecfeed-serve", "--generate-basic-password"]).is_ok()
        );
        assert!(
            super::Args::try_parse_from(["mecfeed-serve", "--print-cert-fingerprint", "c.pem"])
                .is_ok()
        );
        assert!(
            super::Args::try_parse_from([
                "mecfeed-serve",
                "--generate-basic-password",
                "--print-cert-fingerprint",
                "c.pem"
            ])
            .is_err()
        );
        assert!(super::Args::try_parse_from(["mecfeed-serve"]).is_err());
    }

    #[test]
    fn client_ca_conflicts_with_anonymous_mode() {
        use clap::Parser;
        assert!(
            super::Args::try_parse_from([
                "mecfeed-serve",
                "--tls-cert",
                "c",
                "--tls-key",
                "k",
                "--feed-config",
                "f",
                "--snapshot-dir",
                "d",
                "--trusted-snapshot-key",
                "p",
                "--allow-anonymous-feeds",
                "--client-ca",
                "ca.pem",
            ])
            .is_err()
        );
    }

    #[test]
    fn a_certificate_client_needs_client_ca() {
        let json = format!(
            r#"{{"version":1,"clients":[{{"name":"vsrx-ci","cert_sha256":"{}","feeds":["junos-dynamic-address/address"]}}]}}"#,
            "ab".repeat(32)
        );
        let clients = crate::clients::Clients::from_json(json.as_bytes()).expect("clients");
        let error = super::check_client_ca(Some(&clients), None).expect_err("refused");
        assert!(format!("{error:#}").contains("--client-ca"));
        super::check_client_ca(Some(&clients), Some(Path::new("ca.pem"))).expect("ok with CA");
        super::check_client_ca(Some(&panos_clients()), None).expect("basic-only needs no CA");
        super::check_client_ca(None, None).expect("anonymous");
    }

    #[test]
    fn generated_password_matches_its_hash() {
        let random = rustls::crypto::ring::default_provider().secure_random;
        let (password, digest) = super::generate_basic_password(random).expect("password");
        assert_eq!(password.len(), 43);
        assert!(
            password
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_eq!(digest, hex(&Sha256::digest(password.as_bytes())));
        let (other, _) = super::generate_basic_password(random).expect("password");
        assert_ne!(password, other);
    }

    #[test]
    fn cert_fingerprint_is_the_sha256_of_the_first_der() {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["vsrx-ci".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("client.pem");
        std::fs::write(&path, cert.pem()).expect("write pem");
        assert_eq!(
            super::cert_fingerprint(&path).expect("fingerprint"),
            hex(&Sha256::digest(cert.der()))
        );
        std::fs::write(&path, "not a pem").expect("write");
        assert!(super::cert_fingerprint(&path).is_err());
    }

    fn panos_clients() -> crate::clients::Clients {
        let json = format!(
            r#"{{"version":1,"clients":[{{"name":"panosvm","basic_sha256":"{}","feeds":["panos-edl/address"]}}]}}"#,
            hex(&Sha256::digest(PANOS_PASSWORD.as_bytes()))
        );
        crate::clients::Clients::from_json(json.as_bytes()).expect("clients")
    }

    fn app_with_clients(dir: &Path) -> axum::Router {
        router(App {
            snapshot_dir: dir.to_path_buf(),
            allow: vec!["127.0.0.0/8".parse().expect("loopback")],
            policy: empty_policy(),
            trusted: trusted(&[&test_key(1)]),
            clients: Some(std::sync::Arc::new(panos_clients())),
            reload: std::sync::Arc::default(),
            cache: std::sync::Arc::default(),
        })
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))))
    }

    fn basic_header(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{user}:{password}"))
        )
    }

    async fn send_as(
        app: &axum::Router,
        method: Method,
        uri: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
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

    #[tokio::test]
    async fn feeds_need_a_listed_client_and_unknown_paths_do_not_leak() {
        let dir = one_version_dir();
        let app = app_with_clients(dir.path());
        for uri in ["/feeds/panos-edl/address", "/feeds/nope/nothing"] {
            for method in [Method::GET, Method::HEAD] {
                let (status, headers, body) = send_as(&app, method, uri, None).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
                assert_eq!(
                    headers.get(header::WWW_AUTHENTICATE).expect("challenge"),
                    "Basic realm=\"mecfeed\", charset=\"UTF-8\""
                );
                assert!(body.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_user_are_401() {
        let dir = one_version_dir();
        let app = app_with_clients(dir.path());
        for header_value in [
            basic_header("panosvm", "wrong"),
            basic_header("nobody", PANOS_PASSWORD),
        ] {
            let (status, _, body) = send_as(
                &app,
                Method::GET,
                "/feeds/panos-edl/address",
                Some(&header_value),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn a_listed_client_gets_its_feed_and_403_elsewhere() {
        let dir = one_version_dir();
        let good = basic_header("panosvm", PANOS_PASSWORD);
        let app = app_with_clients(dir.path());
        let (status, headers, body) =
            send_as(&app, Method::GET, "/feeds/panos-edl/address", Some(&good)).await;
        assert_eq!(status, StatusCode::OK);
        let (_, anonymous_headers, anonymous_body) = send(
            &app_for_peer(dir.path(), [127, 0, 0, 1]),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        assert_eq!(body, anonymous_body);
        assert_eq!(
            headers.get(header::ETAG),
            anonymous_headers.get(header::ETAG)
        );
        let (status, _, body) =
            send_as(&app, Method::GET, "/feeds/panos-edl/domain", Some(&good)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn healthz_needs_no_client() {
        let dir = one_version_dir();
        let (status, _, _) =
            send_as(&app_with_clients(dir.path()), Method::GET, "/healthz", None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_denied_request_never_logs_the_password() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Captured(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("log buffer").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();
        // Global, not scoped: a scoped default races other tests' callsite registration and flakes.
        tracing::subscriber::set_global_default(subscriber)
            .expect("only this test installs a subscriber");
        let dir = one_version_dir();
        let wrong = basic_header("panosvm", "wrong-password-value");
        let (status, headers, body) = send_as(
            &app_with_clients(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            Some(&wrong),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let logs = String::from_utf8(captured.0.lock().expect("log buffer").clone()).expect("utf8");
        assert!(logs.contains("bad-password"), "{logs}");
        for haystack in [
            logs.as_str(),
            &format!("{headers:?}"),
            &String::from_utf8_lossy(&body),
        ] {
            assert!(!haystack.contains("wrong-password-value"));
            assert!(!haystack.contains(&wrong));
        }
    }

    #[test]
    fn exactly_one_client_mode_is_required() {
        use clap::Parser;
        let base = [
            "mecfeed-serve",
            "--tls-cert",
            "c",
            "--tls-key",
            "k",
            "--feed-config",
            "f",
            "--snapshot-dir",
            "d",
            "--trusted-snapshot-key",
            "p",
        ];
        assert!(super::Args::try_parse_from(base).is_err());
        assert!(
            super::Args::try_parse_from(base.iter().chain(&["--allow-anonymous-feeds"])).is_ok()
        );
        assert!(super::Args::try_parse_from(base.iter().chain(&["--clients-file", "x"])).is_ok());
        assert!(
            super::Args::try_parse_from(base.iter().chain(&[
                "--clients-file",
                "x",
                "--allow-anonymous-feeds"
            ]))
            .is_err()
        );
    }

    fn two_version_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
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
        dir
    }

    fn feed_document_digest(dir: &Path, version: u64) -> String {
        let bytes = std::fs::read(dir.join(format!("versions/{version}/snapshot.json")))
            .expect("read snapshot");
        serde_json::from_slice::<mecfeedmcp_core::SnapshotDocument>(&bytes)
            .expect("parse snapshot")
            .digest
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
        format!("\"sha256-{}\"", hex(&Sha256::digest(body)))
    }

    async fn status_of(app: &axum::Router) -> StatusCode {
        send(app, Method::GET, "/feeds/panos-edl/address", None)
            .await
            .0
    }

    #[tokio::test]
    async fn missing_signature_fails_closed() {
        let dir = one_version_dir();
        std::fs::remove_file(sig_path(dir.path(), 1)).expect("remove");
        assert_eq!(
            status_of(&app(dir.path())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn signature_by_an_untrusted_key_fails_closed() {
        let dir = one_version_dir();
        let digest = feed_document_digest(dir.path(), 1);
        std::fs::write(
            sig_path(dir.path(), 1),
            signature_for(&test_key(9), &digest),
        )
        .expect("write");
        assert_eq!(
            status_of(&app(dir.path())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn signature_over_another_digest_fails_closed() {
        let dir = one_version_dir();
        let other = "ab".repeat(32);
        std::fs::write(sig_path(dir.path(), 1), signature_for(&test_key(1), &other))
            .expect("write");
        assert_eq!(
            status_of(&app(dir.path())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn signature_copied_from_another_version_fails_closed() {
        let dir = two_version_dir();
        std::fs::copy(sig_path(dir.path(), 1), sig_path(dir.path(), 2)).expect("copy");
        assert_eq!(
            status_of(&app(dir.path())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn a_bad_historical_signature_is_not_read() {
        let dir = two_version_dir();
        std::fs::write(sig_path(dir.path(), 1), b"garbage").expect("write");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_symlinked_signature_fails_closed() {
        let dir = one_version_dir();
        let path = sig_path(dir.path(), 1);
        let real = dir.path().join("real.sig");
        std::fs::rename(&path, &real).expect("move");
        std::os::unix::fs::symlink(&real, &path).expect("symlink");
        assert_eq!(
            status_of(&app(dir.path())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn either_of_two_trusted_keys_verifies() {
        let dir = one_version_dir();
        let digest = feed_document_digest(dir.path(), 1);
        std::fs::write(
            sig_path(dir.path(), 1),
            signature_for(&test_key(2), &digest),
        )
        .expect("write");
        let keys = trusted(&[&test_key(1), &test_key(2)]);
        assert_eq!(
            status_of(&app_with_trust(dir.path(), keys)).await,
            StatusCode::OK
        );
    }

    #[test]
    fn trusted_key_files_are_checked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good.pub");
        let bad = dir.path().join("bad.pub");
        std::fs::write(&good, format!("{}\n", public_text(&test_key(1)))).expect("write");
        std::fs::write(&bad, "not a key\n").expect("write");
        assert!(load_trusted_keys(std::slice::from_ref(&good)).is_ok());
        assert!(load_trusted_keys(&[]).is_err());
        assert!(load_trusted_keys(&[good.clone(), good.clone()]).is_err());
        assert!(load_trusted_keys(&[good, bad]).is_err());
        assert!(load_trusted_keys(&[dir.path().join("missing.pub")]).is_err());
    }

    #[tokio::test]
    async fn operator_allowlisted_value_in_a_published_version_fails_closed() {
        let dir = one_version_dir();
        let policy = Policy::try_new(
            vec![],
            vec!["1.0.0.0/24".parse().expect("cidr")],
            Vec::<&str>::new(),
            Limits::default(),
        )
        .expect("policy");
        let app = app_with_policy(dir.path(), [127, 0, 0, 1], policy);
        let (status, _, body) = send(&app, Method::GET, "/feeds/panos-edl/address", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.is_empty());
    }

    #[test]
    fn feed_config_accepts_mcp_keys_and_rejects_bad_input() {
        let example = include_str!("../../../examples/feed.example.json");
        let ok: FeedPolicyConfig = serde_json::from_str(example).expect("example parses");
        ok.policy().expect("policy");
        let with_misp = example.replacen(
            "\"tenant\"",
            "\"misp\": {\"base_url\": \"https://misp.example.org\"}, \"tenant\"",
            1,
        );
        serde_json::from_str::<FeedPolicyConfig>(&with_misp).expect("misp parses");
        let parse = |text: &str| serde_json::from_str::<FeedPolicyConfig>(text);
        assert!(parse(r#"{"version":1,"tenant":"lab","allow_cirds":["1.0.0.0/24"]}"#).is_err());
        assert!(parse(r#"{"tenant":"lab"}"#).is_err());
        assert!(parse(r#"{"version":2}"#).expect("parses").policy().is_err());
        let bad = parse(r#"{"version":1,"allow_cidrs":["not-a-cidr"]}"#).expect("parses");
        assert!(bad.policy().is_err());
        let bad_suffix = parse(r#"{"version":1,"allow_domain_suffixes":["x"]}"#).expect("parses");
        assert!(bad_suffix.policy().is_err());
    }

    #[tokio::test]
    async fn allowlist_entry_matching_only_history_does_not_block_a_clean_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = now() - 10 * DAY;
        let at = now();
        let mut versions = feed_versions();
        publish(
            &mut versions,
            old,
            vec![entry(IndicatorKind::Ip, "1.0.0.1", old, old + DAY)],
        );
        publish(
            &mut versions,
            at,
            vec![entry(IndicatorKind::Ip, "1.0.0.2", at, at + DAY)],
        );
        let second = versions.document(2).expect("v2");
        assert!(second.entries.iter().all(|row| row.value != "1.0.0.1"));
        write_layout(dir.path(), &versions, 2, 2);
        let policy = Policy::try_new(
            vec![],
            vec!["1.0.0.1/32".parse().expect("cidr")],
            Vec::<&str>::new(),
            Limits::default(),
        )
        .expect("policy");
        let app = app_with_policy(dir.path(), [127, 0, 0, 1], policy);
        let (status, _, body) = send(&app, Method::GET, "/feeds/panos-edl/address", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"1.0.0.2\n");
    }

    #[tokio::test]
    async fn a_recorded_broad_exception_in_history_does_not_block_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = now() - 10 * DAY;
        let at = now();
        let permitting = Limits {
            permit_explicit_broad: true,
            ..Limits::default()
        };
        let mut versions = FeedVersions::open(
            Policy::try_new(vec![], vec![], Vec::<&str>::new(), permitting).expect("policy"),
        );
        publish(
            &mut versions,
            old,
            vec![ProposedEntry {
                allow_broad_prefix: true,
                ..entry(IndicatorKind::Cidr, "1.0.0.0/16", old, old + DAY)
            }],
        );
        publish(
            &mut versions,
            at,
            vec![entry(IndicatorKind::Ip, "1.0.0.2", at, at + DAY)],
        );
        write_layout(dir.path(), &versions, 2, 2);
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

    #[tokio::test]
    async fn allowlist_covers_unmatched_routes() {
        let dir = one_version_dir();
        let outsider = app_for_peer(dir.path(), [8, 8, 8, 8]);
        let (status, _, _) = send(&outsider, Method::GET, "/nope", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(&outsider, Method::GET, "/healthz", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(&app(dir.path()), Method::GET, "/nope", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unreadable_snapshot_dir_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = one_version_dir();
        let mode = std::fs::metadata(dir.path()).expect("meta").permissions();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let readable = std::fs::read_dir(dir.path()).is_ok();
        let (status, _, _) = send(
            &app(dir.path()),
            Method::GET,
            "/feeds/panos-edl/address",
            None,
        )
        .await;
        std::fs::set_permissions(dir.path(), mode).expect("restore");
        if !readable {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }
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
