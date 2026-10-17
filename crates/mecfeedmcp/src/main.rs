//! Governed threat-intel feed MCP server executable.

use anyhow::{Context, Result};
use mecfeedmcp::{
    FeedHandler, KNOWN_TOOLS, SighupHandler, install_early_sighup_handler, serve_http,
};
use mecmcp_auth::{NoGrant, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Command, ParsedCli, Transport};
use mecmcp_secret::naming::ServerNaming;
use mecmcp_secret::validate::{CredentialFileRole, CredentialFileSpec, validate_credential_files};
use rmcp::ServiceExt as _;
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Shared mecmcp CLI plus the three standardized change-set flags.
#[derive(Debug, clap::Parser)]
struct ServerCli {
    /// Arguments shared by every mecmcp server.
    #[command(flatten)]
    shared: Cli,

    /// Run without two-person control; change sets are approved on creation.
    #[arg(long)]
    lab_mode: bool,

    /// Absolute path to the change-set state file.
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// How long an approval stays valid, in seconds. Must be greater than zero.
    #[arg(
        long,
        default_value_t = DEFAULT_APPROVAL_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    approval_timeout_secs: u64,

    /// Validate package configuration and SBOM, then exit.
    #[arg(long)]
    validate_package: Option<PathBuf>,

    /// Expose unauthenticated Prometheus metrics at /metrics (streamable-http only).
    #[arg(long)]
    enable_metrics: bool,

    /// Max requests per second per source IP address.
    #[arg(long, default_value_t = 50)]
    max_requests_per_second_per_ip: u64,

    /// Max immediate request burst per source IP address.
    #[arg(long, default_value_t = 100)]
    max_request_burst_per_ip: u64,

    /// Max requests per second per bearer token.
    #[arg(long, default_value_t = 20)]
    max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token.
    #[arg(long, default_value_t = 40)]
    max_request_burst_per_token: u64,
}

const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 900;

#[derive(Debug, Deserialize)]
struct FeedConfig {
    version: u32,
    tenant: String,
    #[serde(default)]
    changeset_state_file: Option<PathBuf>,
    #[serde(default)]
    approval_ttl_secs: Option<u64>,
}

fn server_naming() -> ServerNaming {
    ServerNaming::derive("mecfeedmcp")
}

fn token_store_paths() -> (PathBuf, PathBuf) {
    let naming = server_naming();
    (
        naming.state_dir.join("tokens.json"),
        naming.config_dir.join("tokens.json"),
    )
}

fn credentials_env_path() -> PathBuf {
    server_naming().config_dir.join("credentials.env")
}

#[derive(Debug, PartialEq, Eq)]
enum AuthMode {
    Tokens(PathBuf),
    NoAuth,
}

fn resolve_auth_mode(
    tokens_file: Option<&Path>,
    allow_no_auth: bool,
) -> Result<AuthMode, &'static str> {
    match (tokens_file, allow_no_auth) {
        (Some(path), false) => Ok(AuthMode::Tokens(path.to_owned())),
        (None, true) => Ok(AuthMode::NoAuth),
        (Some(_), true) => Err(
            "--tokens-file and --allow-no-auth are mutually exclusive: pass --tokens-file for an authenticated listener, or --allow-no-auth alone for an unauthenticated loopback one",
        ),
        (None, false) => Err(
            "--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)",
        ),
    }
}

fn resolve_listener_auth_mode(
    transport: Transport,
    tokens_file: Option<&Path>,
    allow_no_auth: bool,
) -> Result<Option<AuthMode>, &'static str> {
    match transport {
        Transport::Stdio => Ok(None),
        Transport::StreamableHttp => resolve_auth_mode(tokens_file, allow_no_auth).map(Some),
    }
}

fn resolve_tokens(configured: &Path) -> Result<mecmcp_auth::ResolvedTokenPath> {
    let (canonical, legacy) = token_store_paths();
    if configured.as_os_str() != canonical.as_os_str() {
        return Ok(mecmcp_auth::ResolvedTokenPath {
            path: configured.to_path_buf(),
            used_fallback: false,
            fallback_from: None,
        });
    }
    mecmcp_auth::resolve_token_path(configured, &legacy).context("resolving token file path")
}

fn ensure_audit_hmac_key(path: &Path) -> Result<()> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    use rand::TryRng as _;
    rand::rngs::SysRng.try_fill_bytes(&mut key).map_err(|e| {
        anyhow::anyhow!("generating audit HMAC key: OS entropy source unavailable: {e}")
    })?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating audit HMAC key file {}", path.display()))?;
        file.write_all(hex_key.as_bytes())
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }

    Ok(())
}

fn reject_unsupported_otel_endpoint(otel_endpoint: Option<&str>) -> Result<()> {
    if otel_endpoint.is_some() {
        anyhow::bail!(
            "--otel-endpoint requires a build of mecfeedmcp with mecmcp-audit's `otel` feature, \
             which this binary does not enable"
        );
    }
    Ok(())
}

fn install_shutdown_signals(shutdown: CancellationToken) -> Result<()> {
    let coordinator = mecmcp_runtime::shutdown::GracefulShutdown::new()
        .context("installing shutdown signal handlers")?;
    let interrupt = coordinator.subscribe();
    tokio::spawn(async move {
        let _coordinator = coordinator;
        interrupt.await;
        shutdown.cancel();
    });
    Ok(())
}

#[cfg(unix)]
fn verify_server_alive(raw_pid: i32) -> Result<()> {
    let pid = rustix::process::Pid::from_raw(raw_pid)
        .ok_or_else(|| anyhow::anyhow!("server PID must be positive"))?;
    rustix::process::test_kill_process(pid).map_err(|error| {
        anyhow::anyhow!("server process {raw_pid} is not alive after SIGHUP: {error}")
    })
}

#[cfg(not(unix))]
fn verify_server_alive(_raw_pid: i32) -> Result<()> {
    anyhow::bail!("--server-pid liveness checks are available only on Unix")
}

fn validate_config_file(package_dir: &Path) -> Result<()> {
    let config_path = package_dir.join("config/feed.json.example");
    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&content).context("config example is not valid JSON")?;
    if value.get("version") != Some(&serde_json::json!(1)) {
        anyhow::bail!("config example version must be 1");
    }
    if !value
        .get("tenant")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        anyhow::bail!("config example tenant must be a non-empty string");
    }
    if value.get("changeset_state_file")
        != Some(&serde_json::json!(
            "/var/lib/mecfeedmcp/changeset-state.json"
        ))
    {
        anyhow::bail!(
            "config example changeset_state_file must be '/var/lib/mecfeedmcp/changeset-state.json'"
        );
    }
    Ok(())
}

fn parse_json_rejecting_duplicate_keys(text: &str) -> Result<serde_json::Value> {
    struct Strict(serde_json::Value);
    struct StrictVisitor;

    impl<'de> serde::de::Visitor<'de> for StrictVisitor {
        type Value = Strict;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON with unique object member names")
        }
        fn visit_unit<E>(self) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Null))
        }
        fn visit_bool<E>(self, v: bool) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }
        fn visit_i64<E>(self, v: i64) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }
        fn visit_u64<E>(self, v: u64) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }
        fn visit_f64<E>(self, v: f64) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }
        fn visit_str<E>(self, v: &str) -> std::result::Result<Strict, E> {
            Ok(Strict(v.into()))
        }
        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Strict, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut items = Vec::new();
            while let Some(Strict(v)) = seq.next_element::<Strict>()? {
                items.push(v);
            }
            Ok(Strict(serde_json::Value::Array(items)))
        }
        fn visit_map<A>(self, mut map: A) -> std::result::Result<Strict, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut out = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                let Strict(value) = map.next_value::<Strict>()?;
                if out.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate object member '{key}'"
                    )));
                }
            }
            Ok(Strict(serde_json::Value::Object(out)))
        }
    }

    impl<'de> serde::Deserialize<'de> for Strict {
        fn deserialize<D>(d: D) -> std::result::Result<Strict, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            d.deserialize_any(StrictVisitor)
        }
    }

    let Strict(value) = serde_json::from_str::<Strict>(text)?;
    Ok(value)
}

fn validate_sbom_file(package_dir: &Path) -> Result<()> {
    let sbom_path = package_dir.join("SBOM.cdx.json");
    let content = fs::read_to_string(&sbom_path)
        .with_context(|| format!("reading {}", sbom_path.display()))?;
    let value = parse_json_rejecting_duplicate_keys(&content)
        .context("SBOM is not valid JSON with unique object members")?;
    if value.get("bomFormat").and_then(|v| v.as_str()) != Some("CycloneDX") {
        anyhow::bail!("SBOM bomFormat must be 'CycloneDX'");
    }
    if value
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("name"))
        .and_then(|n| n.as_str())
        != Some("mecfeedmcp")
    {
        anyhow::bail!("SBOM metadata.component.name must be 'mecfeedmcp'");
    }
    let components = value
        .get("components")
        .and_then(|c| c.as_array())
        .ok_or_else(|| anyhow::anyhow!("SBOM components must be a non-empty array"))?;
    if components.is_empty() {
        anyhow::bail!("SBOM components array must not be empty");
    }
    if !components
        .iter()
        .any(|c| c.get("name").and_then(|n| n.as_str()) == Some("serde"))
    {
        anyhow::bail!("SBOM must contain 'serde' component");
    }
    let expected_mecmcp_components = [
        ("mecmcp-audit", "0.28.1"),
        ("mecmcp-auth", "0.28.1"),
        ("mecmcp-changeset", "0.28.1"),
        ("mecmcp-redact", "0.28.1"),
        ("mecmcp-runtime", "0.28.1"),
        ("mecmcp-secret", "0.28.1"),
        ("mecmcp-server", "0.28.1"),
        ("mecmcp-transport", "0.28.1"),
    ];
    let mut found_mecmcp: Vec<(String, String)> = Vec::new();
    for c in components {
        if let Some(name) = c
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| n.starts_with("mecmcp-"))
        {
            let version = c.get("version").and_then(|v| v.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "SBOM mecmcp-* component '{name}' has missing or non-string version"
                )
            })?;
            found_mecmcp.push((name.to_string(), version.to_string()));
        }
    }
    found_mecmcp.sort();
    let expected: Vec<(String, String)> = expected_mecmcp_components
        .iter()
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .collect();
    if found_mecmcp != expected {
        anyhow::bail!(
            "SBOM mecmcp-* components mismatch. Expected: {expected:?}, Found: {found_mecmcp:?}"
        );
    }
    let normalized = serde_json::to_string(&value)
        .context("re-serializing SBOM for forbidden-string validation")?;
    let contains_forbidden = |needle: &str| content.contains(needle) || normalized.contains(needle);
    if contains_forbidden("v0.8.0") {
        anyhow::bail!("SBOM must not contain 'v0.8.0'");
    }
    if contains_forbidden("70ac3d8fb5f27db3257d11aef28bd09587f085e1") {
        anyhow::bail!("SBOM must not contain forbidden commit hash");
    }
    if contains_forbidden("/home/")
        || contains_forbidden("/workspace/")
        || contains_forbidden("/workspaces/")
    {
        anyhow::bail!("SBOM contains an absolute repository or worktree path");
    }
    Ok(())
}

fn validate_package(package_dir: &Path) -> Result<()> {
    validate_config_file(package_dir).context("config validation failed")?;
    validate_sbom_file(package_dir).context("SBOM validation failed")?;
    Ok(())
}

fn validate_startup_credentials(
    config: &Path,
    credentials_env: Option<&Path>,
    tokens: Option<&Path>,
    audit_hmac_key: Option<&Path>,
) -> Result<()> {
    let mut specs = Vec::with_capacity(4);
    specs.push(CredentialFileSpec {
        path: config,
        role: CredentialFileRole::ConfigNoSecret,
        description: "feed configuration",
        required: true,
    });
    if let Some(path) = credentials_env {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "credentials.env",
            required: false,
        });
    }
    if let Some(path) = tokens {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "bearer token store",
            required: true,
        });
    }
    if let Some(path) = audit_hmac_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit HMAC key",
            required: true,
        });
    }
    validate_credential_files(&specs).map_err(anyhow::Error::from)
}

#[tokio::main]
async fn main() -> Result<()> {
    let sighup_handler: SighupHandler =
        install_early_sighup_handler().context("installing early SIGHUP handler")?;
    let parsed: ParsedCli<ServerCli> = mecmcp_runtime::cli::parse_with_provenance::<ServerCli>(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );

    if let Some(package_dir) = &parsed.cli.validate_package {
        return validate_package(package_dir).map(|()| {
            println!("Package validation successful");
        });
    }

    let ServerCli {
        shared: args,
        lab_mode,
        state_file: cli_state_file,
        approval_timeout_secs: cli_approval_timeout_secs,
        validate_package: _,
        enable_metrics,
        max_requests_per_second_per_ip,
        max_request_burst_per_ip,
        max_requests_per_second_per_token,
        max_request_burst_per_token,
    } = parsed.cli;
    mecmcp_runtime::cli_validate::validate_or_exit(&args);

    let auth_mode = resolve_listener_auth_mode(
        args.transport,
        args.tokens_file.as_deref(),
        args.allow_no_auth,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let tokens_resolved = match &auth_mode {
        Some(AuthMode::Tokens(path)) => Some(resolve_tokens(path)?),
        None | Some(AuthMode::NoAuth) => None,
    };

    if let Some(key_path) = args.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path).context("pre-provisioning audit HMAC key file")?;
    }

    let credentials_env = credentials_env_path();
    validate_startup_credentials(
        &args.device_mapping,
        Some(&credentials_env),
        tokens_resolved
            .as_ref()
            .map(|resolved| resolved.path.as_path()),
        args.audit_hmac_key_file.as_deref(),
    )
    .context("credential file validation")?;

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    reject_unsupported_otel_endpoint(args.otel_endpoint.as_deref())?;
    let audit_sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        otel: None,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("mecfeedmcp_tool_duration_seconds");

    let config_text = fs::read_to_string(&args.device_mapping)
        .with_context(|| format!("loading {}", args.device_mapping.display()))?;
    let config: FeedConfig = serde_json::from_str(&config_text)
        .with_context(|| format!("parsing {}", args.device_mapping.display()))?;
    if config.version != 1 {
        anyhow::bail!("feed.json version must be 1");
    }
    if config.tenant.is_empty() {
        anyhow::bail!("feed.json tenant must be a non-empty string");
    }

    let set_scopes_pid = match args.command.as_ref() {
        Some(Command::Token {
            action: mecmcp_runtime::cli::TokenAction::SetScopes { server_pid, .. },
        }) => *server_pid,
        _ => None,
    };
    if let Some(Command::Token { action }) = args.command {
        mecmcp_runtime::token_cmd::run(action, &[config.tenant], KNOWN_TOOLS)
            .map_err(anyhow::Error::from)?;
        if let Some(pid) = set_scopes_pid {
            tokio::time::sleep(Duration::from_millis(50)).await;
            verify_server_alive(pid)?;
        }
        return Ok(());
    }

    if lab_mode {
        tracing::warn!(
            "--lab-mode: two-person control is DISABLED. This skeleton does not yet \
             implement change sets; the flag is accepted so the packaged CLI surface \
             matches the rest of the fleet."
        );
    }
    let _state_file = cli_state_file.or(config.changeset_state_file);
    let _approval_ttl_secs = config
        .approval_ttl_secs
        .unwrap_or(cli_approval_timeout_secs);

    if args
        .evidence
        .into_config()
        .map_err(anyhow::Error::msg)?
        .is_some()
    {
        anyhow::bail!(
            "SSDF evidence flags are not wired in this empty skeleton; omit them until the \
             change-set lifecycle ships"
        );
    }

    let provider = rustls::crypto::ring::default_provider();
    provider
        .clone()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring crypto provider"))?;

    let shutdown = CancellationToken::new();
    install_shutdown_signals(shutdown.clone())?;

    if matches!(auth_mode, Some(AuthMode::NoAuth)) {
        tracing::warn!(
            "--allow-no-auth: Streamable HTTP accepts unauthenticated requests on loopback"
        );
    }

    let token_store = match tokens_resolved {
        None => None,
        Some(resolved) => {
            let store = Arc::new(
                TokenStoreFile::<NoGrant>::load(&resolved.path)
                    .with_context(|| format!("loading {}", resolved.path.display()))?,
            );
            tracing::info!(
                tokens = store.store().len(),
                path = %resolved.path.display(),
                "token store loaded"
            );
            Some(store)
        }
    };

    sighup_handler
        .configure(audit_sink, token_store.clone())
        .context("configuring SIGHUP handler")?;

    let handler = FeedHandler;
    match args.transport {
        Transport::Stdio => {
            let service = match handler
                .serve_with_ct((tokio::io::stdin(), tokio::io::stdout()), shutdown)
                .await
            {
                Ok(service) => service,
                Err(rmcp::service::ServerInitializeError::Cancelled) => {
                    tracing::info!("shutdown signalled before initialization; exiting cleanly");
                    return Ok(());
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error)).context("starting MCP stdio service");
                }
            };
            service
                .waiting()
                .await
                .context("MCP stdio service exited with error")?;
        }
        Transport::StreamableHttp => {
            let address = format!("{}:{}", args.host, args.port)
                .parse()
                .with_context(|| format!("parsing {}:{}", args.host, args.port))?;
            let tls = match (&args.tls_cert, &args.tls_key) {
                (Some(cert), Some(key)) => Some(
                    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
                        .context("loading listener TLS")?,
                ),
                _ => None,
            };
            let limits = mecmcp_transport::LimitsConfig {
                max_requests_per_second_per_ip,
                max_request_burst_per_ip,
                max_requests_per_second_per_token,
                max_request_burst_per_token,
                ..mecmcp_transport::LimitsConfig::default()
            };
            limits
                .validate()
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            serve_http(
                handler,
                address,
                token_store,
                args.allowed_host,
                args.allowed_origin,
                limits,
                enable_metrics,
                args.allow_insecure_bind,
                tls,
                shutdown,
                Duration::from_secs(10),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuthMode, resolve_auth_mode, resolve_listener_auth_mode};
    use mecmcp_runtime::cli::Transport;
    use std::path::Path;

    #[test]
    fn stdio_never_consults_the_tokens_file() {
        assert_eq!(
            resolve_listener_auth_mode(
                Transport::Stdio,
                Some(Path::new("/does/not/exist/tokens.json")),
                false,
            ),
            Ok(None),
        );
        assert_eq!(
            resolve_listener_auth_mode(Transport::Stdio, None, false),
            Ok(None),
        );
    }

    #[test]
    fn streamable_http_still_requires_an_auth_decision() {
        assert_eq!(
            resolve_listener_auth_mode(Transport::StreamableHttp, None, false),
            Err(
                "--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)"
            ),
        );
        assert_eq!(
            resolve_listener_auth_mode(
                Transport::StreamableHttp,
                Some(Path::new("/var/lib/mecfeedmcp/tokens.json")),
                false,
            ),
            Ok(Some(AuthMode::Tokens(
                Path::new("/var/lib/mecfeedmcp/tokens.json").to_path_buf()
            ))),
        );
        assert_eq!(resolve_auth_mode(None, true), Ok(AuthMode::NoAuth),);
    }
}
