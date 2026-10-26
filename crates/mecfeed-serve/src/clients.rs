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
        // serde echoes unknown field names, which the 1 MiB cap alone does not bound.
        let file: ClientsFile = serde_json::from_slice(bytes).map_err(|error| {
            let message: String = error.to_string().chars().take(200).collect();
            anyhow::anyhow!("parsing client list: {message}")
        })?;
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
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
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
        HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{user}:{password}"))
        ))
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
    fn a_parse_error_does_not_echo_an_unbounded_field_name() {
        let json = format!(r#"{{"version":1,"clients":[],"{}":1}}"#, "x".repeat(5000));
        let error = refused(&json);
        assert!(error.contains("unknown field"), "{error}");
        assert!(error.len() < 400, "{} bytes", error.len());
    }

    #[test]
    fn bad_lists_are_refused() {
        let hash = sha_hex(b"x");
        let one = |client: &str| format!(r#"{{"version":1,"clients":[{client}]}}"#);
        let cases = [
            (
                r#"{"version":1,"clients":[],"extra":1}"#.to_string(),
                "unknown field",
            ),
            (
                r#"{"version":2,"clients":[]}"#.to_string(),
                "version must be 1",
            ),
            (
                one(&format!(
                    r#"{{"name":"a b","basic_sha256":"{hash}","feeds":["panos-edl/address"]}}"#
                )),
                "must match",
            ),
            (
                one(&format!(
                    r#"{{"name":"{}","basic_sha256":"{hash}","feeds":["panos-edl/address"]}}"#,
                    "a".repeat(65)
                )),
                "must match",
            ),
            (
                format!(
                    r#"{{"version":1,"clients":[{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address"]}},{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address"]}}]}}"#
                ),
                "listed twice",
            ),
            (
                one(r#"{"name":"a","basic_sha256":"abc","feeds":["panos-edl/address"]}"#),
                "64 lowercase hex",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{}","feeds":["panos-edl/address"]}}"#,
                    hash.to_uppercase()
                )),
                "64 lowercase hex",
            ),
            (
                one(r#"{"name":"a","feeds":["panos-edl/address"]}"#),
                "needs basic_sha256 or cert_sha256",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":[]}}"#
                )),
                "lists no feeds",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address","panos-edl/address"]}}"#
                )),
                "lists a feed twice",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":["nope/address"]}}"#
                )),
                "not a served",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/nope"]}}"#
                )),
                "not a served",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":["junos-dynamic-address/domain"]}}"#
                )),
                "not a served",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address/x"]}}"#
                )),
                "not a served",
            ),
            (
                one(&format!(
                    r#"{{"name":"a","basic_sha256":"{hash}","feeds":["panos-edl/address"],"role":"x"}}"#
                )),
                "unknown field",
            ),
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
            Err(Denial::FeedNotAllowed {
                client: "panosvm".to_string()
            })
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
            (
                None,
                Some(basic("vsrx-ci", "anything")),
                Denial::BadPassword,
            ),
            (Some([9u8; 32]), None, Denial::CertNotListed),
            (
                Some([9u8; 32]),
                Some(basic("panosvm", "wrong")),
                Denial::BadPassword,
            ),
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
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode([0xff, b':', b'x'])))
                .expect("h"),
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
        assert!(
            clients
                .authorize(None, Some(&lower), "panos-edl/address")
                .is_ok()
        );
    }
}
