# mecfeed-serve client authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** mecfeed-serve serves a feed only to a listed client that has authenticated by HTTP Basic or by a pinned client certificate, unless the operator passes `--allow-anonymous-feeds`.

**Architecture:**
- A new `clients.rs` parses the client list and decides each request.
- A route-layer middleware on `/feeds/{format}/{kind}` turns that decision into 401 or 403.
- A new `tls.rs` builds the rustls config, with an optional client-CA verifier, and wraps axum-server's rustls acceptor so each request carries its connection's client-cert fingerprint.
- Packaging ships an empty starter list, so a fresh install fails closed.

**Tech Stack:** Rust 2024, axum 0.8, axum-server 0.8 (`tls-rustls-no-provider`), rustls 0.23 with ring, `subtle`, `base64`, `tokio-rustls`, bash installer, systemd, Docker.

**Spec:** `docs/superpowers/specs/2026-10-26-serve-client-auth-design.md`

## Global Constraints

- **Dependencies:**
  - No new crate versions in `Cargo.lock`. New direct dependencies may come only from the lockfile: `subtle` 2.6.1, `tokio-rustls` 0.26.6 (`default-features = false`; `aws-lc-rs` must not appear in the lockfile), and `tower` 0.5.3. `base64` moves from dev-dependencies to dependencies.
  - New crates go in root `Cargo.toml` `[workspace.dependencies]`, and the crate uses `x.workspace = true`, matching the existing style.
- **Code rules:**
  - `#![forbid(unsafe_code)]` stays.
  - `scripts/verify-packaging.sh` bans `std::process` in production Rust (`Command::new` only in `*_test.rs` or `tests/`).
  - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and `cargo fmt --all -- --check` must pass at every commit. That includes no `dead_code`, so every task wires what it adds.
- **Exact strings:**
  - flags: `--clients-file`, `--allow-anonymous-feeds`, `--client-ca`, `--generate-basic-password`, `--print-cert-fingerprint`
  - challenge header: `Basic realm="mecfeed", charset="UTF-8"`
  - log reasons: `no-credentials`, `unknown-user`, `bad-password`, `cert-not-listed`, `feed-not-allowed`
  - starter file: `{"version":1,"clients":[]}`
  - path: `/etc/mecfeed-serve/clients.json`
- **Limits:**
  - name charset `[A-Za-z0-9._-]{1,64}`
  - hashes are exactly 64 lowercase hex
  - `Authorization` header cap 1024 bytes
  - client-list file cap 1 MiB (1048576 bytes)
- **Secrets:** the `Authorization` header and any password are never logged or echoed.
- **Commits:** each ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- **Temp files:** temp and build files go under `~/.cache`, never `/tmp`.

---

### Task 1: Client list and feed-route authorization

**Files:**
- Create: `crates/mecfeed-serve/src/clients.rs`
- Modify: `crates/mecfeed-serve/src/main.rs`: `mod clients;`, the `Args` flags, the `App` field, the middleware, the router, and the tests' `app_with` helper
- Modify: `crates/mecfeed-serve/src/snapshots.rs`: make `open_regular` `pub(crate)`
- Modify: `Cargo.toml` (`[workspace.dependencies]`: `subtle = "2"`), `crates/mecfeed-serve/Cargo.toml` (`subtle.workspace = true`, and move `base64.workspace = true` from `[dev-dependencies]` to `[dependencies]`)

**Interfaces:**
- Produces, in `clients.rs`:
  - `pub(crate) struct Clients`
  - `pub(crate) fn load(path: &Path) -> anyhow::Result<Clients>`
  - `impl Clients { pub(crate) fn from_json(bytes: &[u8]) -> anyhow::Result<Self>; pub(crate) fn authorize(&self, peer_cert: Option<&[u8; 32]>, authorization: Option<&HeaderValue>, feed: &str) -> Result<String, Denial> }`
  - `pub(crate) enum Denial { NoCredentials, UnknownUser, BadPassword, CertNotListed, FeedNotAllowed { client: String } }` with `reason(&self) -> &'static str` and `client(&self) -> Option<&str>`
- Produces, in `main.rs`:
  - `App.clients: Option<Arc<Clients>>` (`None` = `--allow-anonymous-feeds`)
  - `const BASIC_CHALLENGE: &str`
  - `async fn require_client(...)`
- Consumes: `crate::parse_format`, `crate::parse_kind` and `crate::hex` (private fns in `main.rs`, visible to the child module), and `crate::snapshots::open_regular`.

- [ ] **Step 1: Add the dependency lines**

Root `Cargo.toml`, in `[workspace.dependencies]` in alphabetical position (after `sha2`, or wherever the alphabetical order puts it):

```toml
subtle = "2"
```

`crates/mecfeed-serve/Cargo.toml`: add `base64.workspace = true` and `subtle.workspace = true` to `[dependencies]` in alphabetical order, and delete `base64.workspace = true` from `[dev-dependencies]`. Then run `cargo metadata --locked --format-version 1 >/dev/null` and check that `git diff Cargo.lock` adds only dependency edges, no new `[[package]]`.

- [ ] **Step 2: Write `clients.rs` with its unit tests (tests first; they fail to compile until the code exists)**

```rust
//! The feed client list: which client may pull which feed, authenticated by
//! HTTP Basic or by a pinned client certificate.

use anyhow::{Context, Result, bail};
use axum::http::HeaderValue;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};
use subtle::ConstantTimeEq;

/// Largest client list read, in bytes.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Largest `Authorization` value inspected, in bytes.
const MAX_AUTHORIZATION_BYTES: usize = 1024;
/// Compared against when a Basic user is unknown or has no hash, so timing
/// does not reveal valid names. No password hashes to all zeros.
const DUMMY_SHA256: [u8; 32] = [0; 32];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientsFile {
    version: u32,
    clients: Vec<ClientEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientEntry {
    name: String,
    #[serde(default)]
    basic_sha256: Option<String>,
    #[serde(default)]
    cert_sha256: Option<String>,
    feeds: Vec<String>,
}

struct Client {
    name: String,
    basic_sha256: Option<[u8; 32]>,
    cert_sha256: Option<[u8; 32]>,
    feeds: BTreeSet<String>,
}

/// A validated client list.
pub(crate) struct Clients {
    clients: Vec<Client>,
}

/// Why a feed request was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Denial {
    /// No usable Basic credentials and no listed certificate.
    NoCredentials,
    /// The Basic user is not in the list.
    UnknownUser,
    /// The Basic password does not match, or the client has no Basic hash.
    BadPassword,
    /// A CA-valid certificate that no client pins, and no Basic credentials.
    CertNotListed,
    /// An identified client asked for a feed it is not listed for.
    FeedNotAllowed {
        /// The identified client.
        client: String,
    },
}

impl Denial {
    /// The log reason.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::NoCredentials => "no-credentials",
            Self::UnknownUser => "unknown-user",
            Self::BadPassword => "bad-password",
            Self::CertNotListed => "cert-not-listed",
            Self::FeedNotAllowed { .. } => "feed-not-allowed",
        }
    }

    /// The identified client, when there is one.
    pub(crate) fn client(&self) -> Option<&str> {
        match self {
            Self::FeedNotAllowed { client } => Some(client),
            _ => None,
        }
    }
}

/// Load and validate the client list at `path`.
///
/// # Errors
///
/// Returns an error when the file is not a regular file, is over 1 MiB, or
/// does not validate.
pub(crate) fn load(path: &Path) -> Result<Clients> {
    let file = crate::snapshots::open_regular(path, "client list")?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading client list {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        bail!("client list {} is larger than 1 MiB", path.display());
    }
    Clients::from_json(&bytes).with_context(|| format!("client list {}", path.display()))
}

impl Clients {
    /// Parse and validate a client list.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first client and field that is not acceptable.
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self> {
        let file: ClientsFile = serde_json::from_slice(bytes).context("parsing client list")?;
        if file.version != 1 {
            bail!("client list version must be 1");
        }
        let mut names = BTreeSet::new();
        let mut clients = Vec::with_capacity(file.clients.len());
        for entry in file.clients {
            if !valid_name(&entry.name) {
                let shown: String = entry.name.chars().take(64).collect();
                bail!("client name {shown:?} must match [A-Za-z0-9._-]{{1,64}}");
            }
            let name = entry.name;
            if !names.insert(name.clone()) {
                bail!("client {name} is listed twice");
            }
            let basic_sha256 = entry
                .basic_sha256
                .as_deref()
                .map(decode_sha256)
                .transpose()
                .with_context(|| format!("client {name}: basic_sha256"))?;
            let cert_sha256 = entry
                .cert_sha256
                .as_deref()
                .map(decode_sha256)
                .transpose()
                .with_context(|| format!("client {name}: cert_sha256"))?;
            if basic_sha256.is_none() && cert_sha256.is_none() {
                bail!("client {name} needs basic_sha256 or cert_sha256");
            }
            if entry.feeds.is_empty() {
                bail!("client {name} lists no feeds");
            }
            let mut feeds = BTreeSet::new();
            for feed in entry.feeds {
                if !served_feed(&feed) {
                    let shown: String = feed.chars().take(64).collect();
                    bail!("client {name}: {shown:?} is not a served <format>/<kind>");
                }
                if !feeds.insert(feed) {
                    bail!("client {name} lists a feed twice");
                }
            }
            clients.push(Client {
                name,
                basic_sha256,
                cert_sha256,
                feeds,
            });
        }
        Ok(Self { clients })
    }

    /// Decide a request for `feed` (`<format>/<kind>`), returning the allowed client's name.
    ///
    /// # Errors
    ///
    /// Returns the [`Denial`] that explains the refusal.
    pub(crate) fn authorize(
        &self,
        peer_cert: Option<&[u8; 32]>,
        authorization: Option<&HeaderValue>,
        feed: &str,
    ) -> Result<String, Denial> {
        let by_cert = peer_cert.and_then(|fingerprint| {
            self.clients.iter().find(|client| {
                client
                    .cert_sha256
                    .is_some_and(|pinned| bool::from(pinned.ct_eq(fingerprint)))
            })
        });
        let basic = self.basic_client(authorization);
        let identified: Vec<&Client> = by_cert
            .into_iter()
            .chain(basic.as_ref().ok().copied())
            .collect();
        if let Some(client) = identified.iter().find(|client| client.feeds.contains(feed)) {
            return Ok(client.name.clone());
        }
        if let Some(client) = identified.first() {
            return Err(Denial::FeedNotAllowed {
                client: client.name.clone(),
            });
        }
        let denial = basic.err().unwrap_or(Denial::NoCredentials);
        if denial == Denial::NoCredentials && peer_cert.is_some() {
            return Err(Denial::CertNotListed);
        }
        Err(denial)
    }

    fn basic_client(&self, authorization: Option<&HeaderValue>) -> Result<&Client, Denial> {
        let (user, password) = authorization
            .and_then(parse_basic)
            .ok_or(Denial::NoCredentials)?;
        let digest: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let Some(client) = self.clients.iter().find(|client| client.name == user) else {
            std::hint::black_box(DUMMY_SHA256.ct_eq(&digest));
            return Err(Denial::UnknownUser);
        };
        let expected = client.basic_sha256.unwrap_or(DUMMY_SHA256);
        if bool::from(expected.ct_eq(&digest)) && client.basic_sha256.is_some() {
            Ok(client)
        } else {
            Err(Denial::BadPassword)
        }
    }
}

/// `(user, password)` from an `Authorization: Basic` value, or `None` when unusable.
fn parse_basic(value: &HeaderValue) -> Option<(String, String)> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_AUTHORIZATION_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let (scheme, encoded) = text.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn decode_sha256(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("must be 64 lowercase hex characters");
    }
    let mut digest = [0u8; 32];
    for (slot, pair) in digest.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(digest)
}

/// Whether `feed` is a `<format>/<kind>` route this server renders.
fn served_feed(feed: &str) -> bool {
    feed.split_once('/').is_some_and(|(format, kind)| {
        matches!(
            (crate::parse_format(format), crate::parse_kind(kind)),
            (Some(format), Some(kind)) if format.supports(kind)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{Clients, Denial};
    use axum::http::HeaderValue;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

    fn sha_hex(bytes: &[u8]) -> String {
        crate::hex(&Sha256::digest(bytes))
    }

    fn basic(user: &str, password: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))))
            .expect("header")
    }

    const CERT: [u8; 32] = [7; 32];

    fn list() -> Clients {
        let json = format!(
            r#"{{"version":1,"clients":[
                {{"name":"panosvm","basic_sha256":"{}","feeds":["panos-edl/address","panos-edl/domain"]}},
                {{"name":"vsrx-ci","cert_sha256":"{}","feeds":["junos-dynamic-address/address"]}}
            ]}}"#,
            sha_hex(b"s3cret"),
            crate::hex(&CERT),
        );
        Clients::from_json(json.as_bytes()).expect("valid list")
    }

    fn refused(json: &str) -> String {
        format!(
            "{:#}",
            Clients::from_json(json.as_bytes()).err().expect("refused")
        )
    }

    #[test]
    fn a_valid_list_loads_and_an_empty_one_is_allowed() {
        let _ = list();
        Clients::from_json(br#"{"version":1,"clients":[]}"#).expect("empty list");
    }

    #[test]
    fn bad_lists_are_refused() {
        let hash = sha_hex(b"x");
        let one = |client: &str| format!(r#"{{"version":1,"clients":[{client}]}}"#);
        let cases = [
            (r#"{"version":1,"clients":[],"extra":1}"#.to_string(), "unknown field"),
            (r#"{"version":2,"clients":[]}"#.to_string(), "version must be 1"),
            (one(&format!(r#"{{"name":"a b","basic_sha256":"{hash}","feeds":["panos-edl/address"]}}"#)), "must match"),
            (one(&format!(r#"{{"name":"{}","basic_sha256":"{hash}","feeds":["panos-edl/address"]}}"#, "a".repeat(65))), "must match"),
            (format!(r#"{{"version":1,"clients":[{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address"]}},{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address"]}}]}}"#), "listed twice"),
            (one(r#"{"name":"a","basic_sha256":"abc","feeds":["panos-edl/address"]}"#), "64 lowercase hex"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{}","feeds":["panos-edl/address"]}}"#, hash.to_uppercase())), "64 lowercase hex"),
            (one(r#"{"name":"a","feeds":["panos-edl/address"]}"#), "needs basic_sha256 or cert_sha256"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":[]}}"#)), "lists no feeds"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address","panos-edl/address"]}}"#)), "lists a feed twice"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":["nope/address"]}}"#)), "not a served"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/nope"]}}"#)), "not a served"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":["junos-dynamic-address/domain"]}}"#)), "not a served"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address/x"]}}"#)), "not a served"),
            (one(&format!(r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address"],"role":"x"}}"#)), "unknown field"),
        ];
        for (json, want) in cases {
            let error = refused(&json);
            assert!(error.contains(want), "{json} -> {error}");
        }
    }

    #[test]
    fn basic_and_certificate_clients_are_authorized_per_feed() {
        let clients = list();
        let good = basic("panosvm", "s3cret");
        assert_eq!(
            clients.authorize(None, Some(&good), "panos-edl/address"),
            Ok("panosvm".to_string())
        );
        assert_eq!(
            clients.authorize(Some(&CERT), None, "junos-dynamic-address/address"),
            Ok("vsrx-ci".to_string())
        );
        assert_eq!(
            clients.authorize(None, Some(&good), "junos-dynamic-address/address"),
            Err(Denial::FeedNotAllowed { client: "panosvm".to_string() })
        );
        // Either identity suffices when both are presented.
        assert_eq!(
            clients.authorize(Some(&CERT), Some(&good), "panos-edl/domain"),
            Ok("panosvm".to_string())
        );
    }

    #[test]
    fn each_refusal_has_its_reason() {
        let clients = list();
        let cases = [
            (None, None, Denial::NoCredentials),
            (None, Some(basic("nobody", "s3cret")), Denial::UnknownUser),
            (None, Some(basic("panosvm", "wrong")), Denial::BadPassword),
            // A certificate-only client cannot use Basic.
            (None, Some(basic("vsrx-ci", "anything")), Denial::BadPassword),
            (Some([9u8; 32]), None, Denial::CertNotListed),
            (Some([9u8; 32]), Some(basic("panosvm", "wrong")), Denial::BadPassword),
        ];
        for (cert, header, want) in cases {
            assert_eq!(
                clients.authorize(cert.as_ref(), header.as_ref(), "panos-edl/address"),
                Err(want)
            );
        }
    }

    #[test]
    fn unusable_authorization_values_are_no_credentials() {
        let clients = list();
        let long = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("panosvm:{}", "a".repeat(1100)))
        ))
        .expect("header");
        let values = [
            HeaderValue::from_static("Bearer abc"),
            HeaderValue::from_static("Basic !!!"),
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("no-colon"))).expect("h"),
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode([0xff, b':', b'x']))).expect("h"),
            long,
        ];
        for value in values {
            assert_eq!(
                clients.authorize(None, Some(&value), "panos-edl/address"),
                Err(Denial::NoCredentials)
            );
        }
        // The scheme is case-insensitive (RFC 7617).
        let lower = HeaderValue::from_str(&format!("basic {}", STANDARD.encode("panosvm:s3cret")))
            .expect("h");
        assert!(clients.authorize(None, Some(&lower), "panos-edl/address").is_ok());
    }
}
```

`cargo fmt` will rewrap the long test lines; that is expected.

- [ ] **Step 3: Make `open_regular` reachable**

In `crates/mecfeed-serve/src/snapshots.rs`, change `fn open_regular(` to `pub(crate) fn open_regular(`. Its doc comment stays.

- [ ] **Step 4: Wire flags, state, middleware and router in `main.rs`**

Add `mod clients;` beside `mod snapshots;`, and `use clients::{Clients, Denial};`.

In `Args`, after `allow_cidr`:

```rust
    /// Feed client list (JSON). Every feed request must come from a listed client.
    #[arg(long, conflicts_with = "allow_anonymous_feeds", required_unless_present = "allow_anonymous_feeds")]
    clients_file: Option<PathBuf>,

    /// Serve feeds to any client the CIDR allowlist admits, without client authentication.
    #[arg(long)]
    allow_anonymous_feeds: bool,
```

In `App`, add:

```rust
    /// Feed clients; `None` when `--allow-anonymous-feeds` was given.
    clients: Option<Arc<Clients>>,
```

In `main`, after `load_trusted_keys`:

```rust
    let clients = match &args.clients_file {
        Some(path) => Some(Arc::new(clients::load(path)?)),
        None => {
            tracing::warn!("--allow-anonymous-feeds: feeds are served without client authentication");
            None
        }
    };
```

and add `clients,` to the `App { .. }` literal.

Add, next to `require_allowed_client`:

```rust
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
                    [(header::WWW_AUTHENTICATE, HeaderValue::from_static(BASIC_CHALLENGE))],
                )
                    .into_response()
            }
        }
    }
}
```

(`None` for the peer certificate is deliberate: Task 3 passes the connection's fingerprint.)

Change the feed route in `router` to:

```rust
        .route(
            "/feeds/{format}/{kind}",
            any(feed).route_layer(middleware::from_fn_with_state(app.clone(), require_client)),
        )
```

- [ ] **Step 5: Update test helpers and add the router tests (in `main.rs`'s `tests` module)**

In `app_with`, add `clients: None,` to the `App` literal, so every existing test runs anonymous mode unchanged. Add:

```rust
    const PANOS_PASSWORD: &str = "s3cret-password";

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
        format!("Basic {}", BASE64_STANDARD.encode(format!("{user}:{password}")))
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
        for header_value in [basic_header("panosvm", "wrong"), basic_header("nobody", PANOS_PASSWORD)] {
            let (status, _, body) =
                send_as(&app, Method::GET, "/feeds/panos-edl/address", Some(&header_value)).await;
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
        let (_, anonymous_headers, anonymous_body) =
            send(&app_for_peer(dir.path(), [127, 0, 0, 1]), Method::GET, "/feeds/panos-edl/address", None).await;
        assert_eq!(body, anonymous_body);
        assert_eq!(headers.get(header::ETAG), anonymous_headers.get(header::ETAG));
        let (status, _, body) =
            send_as(&app, Method::GET, "/feeds/panos-edl/domain", Some(&good)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn healthz_needs_no_client() {
        let dir = one_version_dir();
        let (status, _, _) = send_as(&app_with_clients(dir.path()), Method::GET, "/healthz", None).await;
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
        let _guard = tracing::subscriber::set_default(subscriber);
        let dir = one_version_dir();
        let wrong = basic_header("panosvm", "wrong-password-value");
        let (status, headers, body) =
            send_as(&app_with_clients(dir.path()), Method::GET, "/feeds/panos-edl/address", Some(&wrong)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let logs = String::from_utf8(captured.0.lock().expect("log buffer").clone()).expect("utf8");
        assert!(logs.contains("bad-password"), "{logs}");
        for haystack in [logs.as_str(), &format!("{headers:?}"), &String::from_utf8_lossy(&body)] {
            assert!(!haystack.contains("wrong-password-value"));
            assert!(!haystack.contains(&wrong));
        }
    }
```

Also add a CLI test that the two modes are exclusive and one is required:

```rust
    #[test]
    fn exactly_one_client_mode_is_required() {
        use clap::Parser;
        let base = [
            "mecfeed-serve", "--tls-cert", "c", "--tls-key", "k", "--feed-config", "f",
            "--snapshot-dir", "d", "--trusted-snapshot-key", "p",
        ];
        assert!(super::Args::try_parse_from(base).is_err());
        assert!(super::Args::try_parse_from(base.iter().chain(&["--allow-anonymous-feeds"])).is_ok());
        assert!(super::Args::try_parse_from(base.iter().chain(&["--clients-file", "x"])).is_ok());
        assert!(super::Args::try_parse_from(
            base.iter().chain(&["--clients-file", "x", "--allow-anonymous-feeds"])
        )
        .is_err());
    }
```

Keep the existing `use super::{...}` list in sync. If `tracing` and `tracing_subscriber` are not already direct dependencies of mecfeed-serve, check `Cargo.toml` (both are used by `main`). `tracing::subscriber::set_default` is thread-local; `#[tokio::test]` uses a current-thread runtime, so the guard covers the request.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p mecfeed-serve --locked`
Expected: all pass. The new router tests fail on the old code: without `require_client`, a feed returns 200 without credentials.

Show RED once: temporarily replace the `route_layer(...)` line with the old route, run `cargo test -p mecfeed-serve --locked feeds_need_a_listed_client`, see it fail, and restore it.

- [ ] **Step 7: Lint and commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
scripts/verify-packaging.sh
git add Cargo.toml Cargo.lock crates/mecfeed-serve
git commit -m "Authenticate and authorize feed clients from a client list

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

`scripts/verify-packaging.sh` may fail here, because the packaged unit and Dockerfile do not yet pass `--clients-file`. If it fails only for that reason, note it in the report; Task 4 fixes it. Any other failure must be fixed.

---

### Task 2: `--client-ca` rule and the two helpers

**Files:**
- Modify: `crates/mecfeed-serve/src/main.rs` (`Args`, `main`, new helper fns, tests)
- Modify: `crates/mecfeed-serve/src/clients.rs` (`needs_client_ca`)

**Interfaces:**
- Consumes: `Clients` from Task 1.
- Produces:
  - `impl Clients { pub(crate) fn needs_client_ca(&self) -> bool }`
  - `fn check_client_ca(clients: Option<&Clients>, client_ca: Option<&std::path::Path>) -> Result<()>`
  - `fn generate_basic_password(random: &dyn rustls::crypto::SecureRandom) -> Result<(String, String)>`
  - `fn cert_fingerprint(path: &std::path::Path) -> Result<String>`
  - `Args.client_ca: Option<PathBuf>`, which Task 3 passes into TLS

- [ ] **Step 1: Write the failing tests (main.rs tests module)**

```rust
    #[test]
    fn helpers_parse_without_serving_flags() {
        use clap::Parser;
        assert!(super::Args::try_parse_from(["mecfeed-serve", "--generate-basic-password"]).is_ok());
        assert!(super::Args::try_parse_from(["mecfeed-serve", "--print-cert-fingerprint", "c.pem"]).is_ok());
        assert!(super::Args::try_parse_from([
            "mecfeed-serve", "--generate-basic-password", "--print-cert-fingerprint", "c.pem"
        ])
        .is_err());
        assert!(super::Args::try_parse_from(["mecfeed-serve"]).is_err());
    }

    #[test]
    fn client_ca_conflicts_with_anonymous_mode() {
        use clap::Parser;
        assert!(super::Args::try_parse_from([
            "mecfeed-serve", "--tls-cert", "c", "--tls-key", "k", "--feed-config", "f",
            "--snapshot-dir", "d", "--trusted-snapshot-key", "p",
            "--allow-anonymous-feeds", "--client-ca", "ca.pem",
        ])
        .is_err());
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
        assert!(password.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
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
```

Run: `cargo test -p mecfeed-serve --locked`. Expected: compile errors for the missing items (RED).

- [ ] **Step 2: Make the serving flags optional for the helpers, and add the new flags**

In `Args`, change `tls_cert`, `tls_key`, `feed_config` and `snapshot_dir` to `Option<PathBuf>`, each with:

```rust
    #[arg(long, required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"])]
```

Change `trusted_snapshot_key` from `required = true` to `required_unless_present_any = ["generate_basic_password", "print_cert_fingerprint"]`. Change `clients_file`'s `required_unless_present = "allow_anonymous_feeds"` to `required_unless_present_any = ["allow_anonymous_feeds", "generate_basic_password", "print_cert_fingerprint"]`. Then add:

```rust
    /// PEM CA certificates that sign client certificates. Required when a client has `cert_sha256`.
    #[arg(long, value_name = "PEM", conflicts_with = "allow_anonymous_feeds")]
    client_ca: Option<PathBuf>,

    /// Print a new Basic password on stdout and its `basic_sha256` on stderr, then exit.
    #[arg(long, conflicts_with = "print_cert_fingerprint")]
    generate_basic_password: bool,

    /// Print the SHA-256 of the first certificate in a PEM file (for `cert_sha256`), then exit.
    #[arg(long, value_name = "PEM")]
    print_cert_fingerprint: Option<PathBuf>,
```

- [ ] **Step 3: Implement the helpers and the startup rule**

In `clients.rs`:

```rust
    /// Whether any client authenticates by certificate, which needs `--client-ca`.
    pub(crate) fn needs_client_ca(&self) -> bool {
        self.clients.iter().any(|client| client.cert_sha256.is_some())
    }
```

In `main.rs`:

```rust
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
```

(Add `use base64::Engine;` if needed.)

In `main`, right after `let args = Args::parse();` and before the snapshot-dir check:

```rust
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
```

Remove the later `let provider = ...` line, keeping its `install_default` call. Use the unwrapped locals where `args.tls_cert`, `args.tls_key`, `args.feed_config` and `args.snapshot_dir` were used. After loading `clients`, call:

```rust
    check_client_ca(clients.as_deref(), args.client_ca.as_deref())?;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p mecfeed-serve --locked`. Expected: all pass.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
git add crates/mecfeed-serve
git commit -m "Require --client-ca for certificate clients, and add password and fingerprint helpers

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Client-certificate TLS and the per-connection fingerprint

**Files:**
- Create: `crates/mecfeed-serve/src/tls.rs` (with a `server_config` unit test)
- Test: `crates/mecfeed-serve/src/main.rs` tests module (the 4 TLS integration tests)
- Modify: `crates/mecfeed-serve/src/main.rs`: `mod tls;`, remove `load_tls` (it moves), use the new acceptor, and pass the fingerprint into `authorize`
- Modify: `Cargo.toml` (`[workspace.dependencies]`: `tokio-rustls = { version = "0.26", default-features = false }`, `tower = "0.5"`), `crates/mecfeed-serve/Cargo.toml` (`tokio-rustls.workspace = true`, `tower.workspace = true`; the dev-dependency `tower = { version = "0.5.3", features = ["util"] }` stays)

**Interfaces:**
- Consumes: `Args.client_ca` (Task 2) and `require_client` (Task 1).
- Produces:
  - `pub(crate) fn server_config(cert_path: &Path, key_path: &Path, client_ca: Option<&Path>, provider: Arc<CryptoProvider>) -> Result<Arc<ServerConfig>>`
  - `#[derive(Clone, Copy, Debug)] pub(crate) struct PeerCert(pub(crate) Option<[u8; 32]>)`
  - `#[derive(Clone)] pub(crate) struct PeerCertAcceptor` with `PeerCertAcceptor::new(config: RustlsConfig) -> Self`, implementing `axum_server::accept::Accept<I, S>`

- [ ] **Step 1: Write the failing TLS tests**

The integration tests go in `main.rs`'s existing `tests` module, so they reuse `one_version_dir`, `empty_policy`, `trusted`, `test_key` and `router`. A unit test for `server_config` goes in `tls.rs`.

In `main.rs` tests, add `use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};`, `use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};` and `use tokio::io::{AsyncReadExt, AsyncWriteExt};`, then:

```rust
    struct Pki {
        ca: CertifiedIssuer<'static, KeyPair>,
    }

    impl Pki {
        fn new() -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            Self {
                ca: CertifiedIssuer::self_signed(params, KeyPair::generate().expect("key"))
                    .expect("ca"),
            }
        }

        /// A leaf for `name`: (cert DER, key DER, cert PEM, key PEM).
        fn leaf(
            &self,
            name: &str,
            usage: ExtendedKeyUsagePurpose,
        ) -> (CertificateDer<'static>, PrivateKeyDer<'static>, String, String) {
            let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate().expect("key");
            let cert = params.signed_by(&key, &self.ca).expect("leaf");
            (
                cert.der().clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                cert.pem(),
                key.serialize_pem(),
            )
        }
    }

    /// Serve the real router over TLS with `--client-ca` set to `pki`'s CA.
    async fn start_tls(dir: &Path, pki: &Pki, clients_json: &str) -> SocketAddr {
        let files = tempfile::tempdir().expect("tls files");
        let (_, _, cert_pem, key_pem) = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
        let (cert_path, key_path, ca_path) = (
            files.path().join("tls.crt"),
            files.path().join("tls.key"),
            files.path().join("client-ca.pem"),
        );
        std::fs::write(&cert_path, cert_pem).expect("cert");
        std::fs::write(&key_path, key_pem).expect("key");
        std::fs::write(&ca_path, pki.ca.pem()).expect("ca");
        let config = crate::tls::server_config(
            &cert_path,
            &key_path,
            Some(&ca_path),
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        )
        .expect("server config");
        let app = App {
            snapshot_dir: dir.to_path_buf(),
            allow: vec!["127.0.0.0/8".parse().expect("loopback")],
            policy: empty_policy(),
            trusted: trusted(&[&test_key(1)]),
            clients: Some(std::sync::Arc::new(
                crate::clients::Clients::from_json(clients_json.as_bytes()).expect("clients"),
            )),
            reload: std::sync::Arc::default(),
            cache: std::sync::Arc::default(),
        };
        let handle = axum_server::Handle::new();
        let server = axum_server::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .handle(handle.clone())
            .acceptor(crate::tls::PeerCertAcceptor::new(
                axum_server::tls_rustls::RustlsConfig::from_config(config),
            ));
        tokio::spawn(server.serve(router(app).into_make_service_with_connect_info::<SocketAddr>()));
        handle.listening().await.expect("bound")
    }

    /// GET the panos-edl address feed over TLS; returns the raw response.
    async fn tls_get(
        addr: SocketAddr,
        pki: &Pki,
        client: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
        authorization: Option<String>,
    ) -> std::io::Result<String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pki.ca.der().clone()).expect("root");
        let builder = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots);
        let config = match client {
            Some((cert, key)) => builder.with_client_auth_cert(vec![cert], key).expect("client cert"),
            None => builder.with_no_client_auth(),
        };
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
            .connect(ServerName::try_from("localhost").expect("name"), tcp)
            .await?;
        let mut request =
            String::from("GET /feeds/panos-edl/address HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(value) = authorization {
            request.push_str(&format!("Authorization: {value}\r\n"));
        }
        request.push_str("\r\n");
        tls.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await?;
        Ok(String::from_utf8_lossy(&response).into_owned())
    }

    fn tls_clients(pinned: &CertificateDer<'_>) -> String {
        format!(
            r#"{{"version":1,"clients":[
                {{"name":"vsrx-ci","cert_sha256":"{}","feeds":["panos-edl/address"]}},
                {{"name":"panosvm","basic_sha256":"{}","feeds":["panos-edl/address"]}}
            ]}}"#,
            hex(&Sha256::digest(pinned.as_ref())),
            hex(&Sha256::digest(b"pw")),
        )
    }

    #[tokio::test]
    async fn a_pinned_client_certificate_gets_the_feed() {
        let dir = one_version_dir();
        let pki = Pki::new();
        let (cert, key, _, _) = pki.leaf("vsrx-ci", ExtendedKeyUsagePurpose::ClientAuth);
        let addr = start_tls(dir.path(), &pki, &tls_clients(&cert)).await;
        let response = tls_get(addr, &pki, Some((cert, key)), None).await.expect("response");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn a_ca_signed_but_unlisted_certificate_is_401() {
        let dir = one_version_dir();
        let pki = Pki::new();
        let (pinned, _, _, _) = pki.leaf("vsrx-ci", ExtendedKeyUsagePurpose::ClientAuth);
        let (other, other_key, _, _) = pki.leaf("other", ExtendedKeyUsagePurpose::ClientAuth);
        let addr = start_tls(dir.path(), &pki, &tls_clients(&pinned)).await;
        let response = tls_get(addr, &pki, Some((other, other_key)), None).await.expect("response");
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }

    #[tokio::test]
    async fn a_certificate_from_another_ca_fails_the_handshake() {
        let dir = one_version_dir();
        let pki = Pki::new();
        let (pinned, _, _, _) = pki.leaf("vsrx-ci", ExtendedKeyUsagePurpose::ClientAuth);
        let foreign = Pki::new();
        let (cert, key, _, _) = foreign.leaf("vsrx-ci", ExtendedKeyUsagePurpose::ClientAuth);
        let addr = start_tls(dir.path(), &pki, &tls_clients(&pinned)).await;
        // TLS 1.3 may report the rejection on the first read rather than at connect.
        match tls_get(addr, &pki, Some((cert, key)), None).await {
            Ok(response) => assert!(!response.starts_with("HTTP/"), "{response}"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn no_certificate_with_good_basic_gets_the_feed() {
        let dir = one_version_dir();
        let pki = Pki::new();
        let (pinned, _, _, _) = pki.leaf("vsrx-ci", ExtendedKeyUsagePurpose::ClientAuth);
        let addr = start_tls(dir.path(), &pki, &tls_clients(&pinned)).await;
        let response = tls_get(addr, &pki, None, Some(basic_header("panosvm", "pw")))
            .await
            .expect("response");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
```

In `tls.rs`, add:

```rust
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
```

`cargo fmt` rewraps long lines, and `clippy` may prefer `if let Ok(response) = ...` for the `match` in the other-CA test, which is fine. If `axum_server::Handle::new()` needs a type parameter in 0.8, use `axum_server::Handle::<SocketAddr>::new()`.

Run: `cargo test -p mecfeed-serve --locked`. Expected: compile failure, because `crate::tls` does not exist (RED).

- [ ] **Step 2: Implement `tls.rs`**

```rust
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
                anyhow::bail!("client CA file {} contained no certificates", path.display());
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
```

If the trait bounds do not compile against axum-server 0.8.0 exactly as written, adjust the bounds only. Keep the behavior and the public names, and record the change in the report. Reference: `~/.cargo/registry/src/*/axum-server-0.8.0/src/{accept.rs,server.rs,tls_rustls/mod.rs}`.

- [ ] **Step 3: Use it from `main.rs`**

- Add `mod tls;`.
- Delete `load_tls`, and the imports only it used.
- Replace the `load_tls(...)` call with `tls::server_config(&tls_cert, &tls_key, args.client_ca.as_deref(), Arc::new(provider))?`. Keep `provider.clone().install_default()` before it.
- Replace the serve call with:

```rust
    axum_server::bind(args.listen)
        .acceptor(tls::PeerCertAcceptor::new(
            axum_server::tls_rustls::RustlsConfig::from_config(tls),
        ))
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("feed server exited")?;
```

In `require_client`, pass the fingerprint:

```rust
    let peer = request.extensions().get::<tls::PeerCert>().and_then(|peer| peer.0);
    match clients.authorize(peer.as_ref(), request.headers().get(header::AUTHORIZATION), &feed) {
```

- [ ] **Step 4: Run all serve tests, then the workspace**

Run: `cargo test -p mecfeed-serve --locked`, then `cargo test --workspace --locked`. Expected: all pass, including the 4 TLS tests and the existing router tests.

- [ ] **Step 5: Check the lockfile, lint and commit**

`git diff Cargo.lock` must add no `[[package]]`, and `grep -c 'name = "aws-lc-rs"' Cargo.lock` must print 0.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo deny check licenses bans sources
git add Cargo.toml Cargo.lock crates/mecfeed-serve
git commit -m "Verify optional client certificates and pin them per connection

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Packaging: unit, installer starter list, warning, smoke tests

**Files:**
- Modify: `packaging/systemd/mecfeed-serve.service`
- Modify: `packaging/lxc/install.sh`
- Modify: `packaging/tests/package-smoke.sh`
- Modify: `scripts/verify-packaging.sh`

**Interfaces:**
- Consumes: the `--clients-file` and `--allow-anonymous-feeds` flags (Task 1).
- Produces: the installed `/etc/mecfeed-serve/clients.json` (starter `{"version":1,"clients":[]}`, mode 0640), and the serve unit passing `--clients-file ${CREDENTIALS_DIRECTORY}/clients.json`.

- [ ] **Step 1: Unit**

In `mecfeed-serve.service`, add under the feed.json `LoadCredential` line:

```ini
# clients.json stays 0640 root:root; systemd hands serve a private copy at each start.
LoadCredential=clients.json:/etc/mecfeed-serve/clients.json
```

Change the last two ExecStart lines to:

```ini
    --trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub \
    --clients-file ${CREDENTIALS_DIRECTORY}/clients.json
```

- [ ] **Step 2: Installer**

1. Next to `signing_pub_path=...` (about line 211):

   ```bash
   clients_path="$serve_config_dir/clients.json"
   ```

   Add `"$clients_path"` to `managed_destinations`, and `"${clients_tmp:-}"` to `cleanup_tmp_files`'s `rm -f` list.

2. Directly after the `.pub` `mv -fT` (about line 426):

   ```bash
   # Starter client list: empty, so every feed answers 401 until an operator adds a client.
   reject_unsafe_file "$clients_path"
   if [[ ! -e "$clients_path" ]]; then
       clients_tmp=$(mktemp "$serve_config_dir/.clients.json.XXXXXX")
       printf '%s\n' '{"version":1,"clients":[]}' >"$clients_tmp"
       chmod 0640 "$clients_tmp"
       mv -fT -- "$clients_tmp" "$clients_path"
   fi
   ```

   (The directory is root-only by `require_root_only_dir`, so check-then-rename cannot be raced.)

3. Generalize `warn_if_exec_start_lacks` to accept one or more alternative flags. It warns only when none is present:

   ```bash
   warn_if_exec_start_lacks() {
       local unit=$1 dropins patterns=() wanted flag
       shift
       for flag in "$@"; do
           patterns+=(-e "$flag")
       done
       printf -v wanted '%s or ' "$@"
       wanted=${wanted% or }
       # (body unchanged up to the grep)
       ... | grep -Fq "${patterns[@]}" \
           || printf '%s\n' "warning: the ExecStart from $unit and its drop-ins lacks $wanted, so the service will not start; re-run with MECFEEDMCP_FORCE_UNIT=1 or fix the unit and its drop-ins in $unit.d" >&2
   }
   ```

   A single flag gives the exact old message, `lacks --trusted-snapshot-key`, so the existing smoke greps keep working. After the existing serve call, add:

   ```bash
   warn_if_exec_start_lacks "$serve_unit_path" --clients-file --allow-anonymous-feeds
   ```

4. In the final `printf` block, add after step 5:

   ```bash
       '6. Add feed clients: mecfeed-serve --generate-basic-password prints a password (give it to the firewall) and its basic_sha256 (put it in /etc/mecfeed-serve/clients.json with the feeds that client may pull), then restart mecfeed-serve. Until then every feed answers 401.' \
   ```

- [ ] **Step 3: verify-packaging**

In `scripts/verify-packaging.sh`, replace the line `require '    --trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub' packaging/systemd/mecfeed-serve.service` with:

```bash
require '    --trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub \' packaging/systemd/mecfeed-serve.service
require '    --clients-file ${CREDENTIALS_DIRECTORY}/clients.json' packaging/systemd/mecfeed-serve.service
require 'LoadCredential=clients.json:/etc/mecfeed-serve/clients.json' packaging/systemd/mecfeed-serve.service
```

If shellcheck flags the `${CREDENTIALS_DIRECTORY}` literal in single quotes (SC2016), add `# shellcheck disable=SC2016` above it, as the file already does elsewhere. Also grep the installer's `validate_package` section for serve-unit pins, and update any that pin the old last ExecStart line.

- [ ] **Step 4: Smoke tests (write first, run RED against the old installer, then GREEN)**

In `package-smoke.sh`, after the first `stage_install` and its existing assertions:

```bash
stage_clients="$stage_root/etc/mecfeed-serve/clients.json"
[[ $(<"$stage_clients") == '{"version":1,"clients":[]}' ]] || { printf '%s\n' 'starter clients.json is wrong' >&2; exit 1; }
[[ $(stat -c %a "$stage_clients") == 640 ]] || { printf '%s\n' 'starter clients.json is not 0640' >&2; exit 1; }
if grep -Fq -- 'lacks --clients-file' "$work_dir/stale-unit.err"; then
    printf '%s\n' 'installer warned about the packaged mecfeed-serve unit (clients)' >&2
    exit 1
fi
```

Before the second `stage_install`, overwrite the file with a custom list, and assert afterwards that it is byte-identical:

```bash
printf '%s\n' '{"version":1,"clients":[{"name":"x","basic_sha256":"'"$(printf '%064d' 0)"'","feeds":["panos-edl/address"]}]}' >"$stage_clients"
sha256sum "$stage_clients" >"$work_dir/clients.sha256"
# ... existing second stage_install ...
sha256sum -c "$work_dir/clients.sha256" >/dev/null
```

In the drop-in case, the stale serve drop-in has neither flag, so also assert `grep -Fq -- 'lacks --clients-file or --allow-anonymous-feeds' "$work_dir/dropin.err"`. Then add a second serve drop-in, `20-anon.conf`, whose `[Service]` ExecStart has `--trusted-snapshot-key x --allow-anonymous-feeds`. Re-run, and assert that neither `lacks --clients-file` nor `lacks --trusted-snapshot-key` appears.

- [ ] **Step 5: Run and commit**

```bash
shellcheck -x packaging/lxc/install.sh packaging/tests/package-smoke.sh scripts/verify-packaging.sh
scripts/verify-packaging.sh
MECFEEDMCP_ALLOW_DIRTY=1 scripts/build-package.sh
git add packaging scripts
git commit -m "Ship a starter client list and pass it to mecfeed-serve

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

`verify-packaging` may still fail here on the Dockerfile and CI pins, which Task 5 handles. If it does, run only the smoke suite: `packaging/tests/package-smoke.sh <built package dir>` (see how `scripts/build-package.sh` invokes it), and note that in the report.

---

### Task 5: Docker, CI, docs and CHANGELOG

**Files:**
- Modify: `Dockerfile.serve`
- Modify: `.github/workflows/ci.yml` (step "Verify feed-server TLS paths survive --listen override")
- Modify: `docs/operations.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: every flag and file from Tasks 1-4.

- [ ] **Step 1: Dockerfile.serve**

ENTRYPOINT ends:

```dockerfile
    "--trusted-snapshot-key", "/etc/mecfeed-serve/snapshot-signing.pub", \
    "--clients-file", "/etc/mecfeed-serve/clients.json"]
```

Update the comment above it to `TLS, snapshot, trust and client-list paths live in ENTRYPOINT so an operator --listen override cannot drop them.`

- [ ] **Step 2: CI**

In the step "Verify feed-server TLS paths survive --listen override", add:

```yaml
          echo "$argv" | grep -q -- '/etc/mecfeed-serve/clients.json' || { echo "FAIL: --clients-file missing from argv"; exit 1; }
```

- [ ] **Step 3: docs/operations.md: new "## Client authentication" section, before "## Tokens and audit"**

It must cover, in the doc's existing voice (short paragraphs and numbered steps):
1. **What it does.** Every feed request needs a listed client. 401 means no or wrong credentials, and 403 means the feed is not in the client's list. `/healthz` is open to the CIDR allowlist. `--allow-anonymous-feeds` is the explicit opt-out.
2. **The file format.** Use the JSON example from the spec, and list the rules: name charset, 64 lowercase hex, `feeds` values, no duplicates, and an empty list closes every feed.
3. **Add a Basic client.** Run `mecfeed-serve --generate-basic-password`: stdout is the password, which goes to the firewall, and stderr is `basic_sha256: …`, which goes in the file. Then `systemctl restart mecfeed-serve`. The password is shown once and never stored.
4. **PAN-OS EDL.** The source URL is `https://<serve host>:8443/feeds/panos-edl/<kind>`. The certificate profile must trust the CA that signed serve's TLS cert, and the client authentication username and password are the client's name and password. Client authentication appears only for an HTTPS source that has a certificate profile.
5. **SRX Basic** (Junos 25.2R1+). Set `user-name` and `password` under the feed server, with the URL `https://<serve host>:8443/feeds/junos-dynamic-address/<kind>`.
6. **SRX mTLS.**
   - Issue the SRX a client cert from a client CA.
   - Start serve with `--client-ca <ca.pem>`. In the systemd drop-in that is a copied ExecStart plus the flag, then `daemon-reload` and restart. In Docker, mount the CA and pass the flag after the image name, re-passing `--listen` and every `--allow-cidr`.
   - Pin `mecfeed-serve --print-cert-fingerprint <srx-cert.pem>` as `cert_sha256`.
   - On the SRX, reference the local cert in the SSL initiation profile.
7. **Rotation.** Edit the file and restart. Renewing a cert changes its fingerprint.
8. **Upgrade (systemd/LXC).**
   1. Re-run the installer with `MECFEEDMCP_FORCE_UNIT=1`. It writes the starter list.
   2. Add the clients.
   3. `systemctl daemon-reload && systemctl restart mecfeed-serve`.
   4. Set credentials on each firewall.

   Until step 2, every feed answers 401.
9. **Upgrade (Docker).** Create `clients.json`, readable by uid 65532 (`0644` is fine: it holds only hashes of 32-byte secrets and fingerprints). Mount it at `/etc/mecfeed-serve/clients.json:ro`, and recreate the serve container.

Also, in the "## Docker" section's serve `docker run` example, add the `clients.json` mount wherever the `.pub` mount appears.

- [ ] **Step 4: CHANGELOG**

Add under `## 0.1.0 — unreleased`:

```markdown
- **Breaking:** mecfeed-serve serves feeds only to clients listed in `--clients-file`, authenticated by HTTP Basic (generated password, stored as SHA-256) or by a client certificate pinned by fingerprint under `--client-ca`. `--allow-anonymous-feeds` restores CIDR-only access. The installer writes an empty `/etc/mecfeed-serve/clients.json`, so feeds answer 401 until clients are added (see `docs/operations.md`, "Client authentication").
```

- [ ] **Step 5: Verify and commit**

```bash
scripts/verify-packaging.sh
MECFEEDMCP_ALLOW_DIRTY=1 scripts/build-package.sh
git add Dockerfile.serve .github/workflows/ci.yml docs/operations.md CHANGELOG.md
git commit -m "Pass the client list in the serve image, and document client authentication

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

If Docker is available, also build `Dockerfile.serve` locally and check that the argv contains `/etc/mecfeed-serve/clients.json`, as the CI step does. Report whether you ran this.
