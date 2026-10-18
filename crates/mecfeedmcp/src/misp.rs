//! Read-only MISP attribute search. The API key never appears in config JSON.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use mecfeedmcp_core::IndicatorKind;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_openapi::expand_path;
use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};
use serde_json::{Value, json};
use thiserror::Error;

use crate::config::MispConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONCURRENT: usize = 4;
const MAX_QUEUED: usize = 8;
const MAX_QUERY_BYTES: usize = 256;
const SEARCH_PATH: &str = "/attributes/restSearch";
const SOURCE: &str = "misp";
const DEFAULT_CONFIDENCE: u8 = 50;

const MISP_IP_TYPES: &[&str] = &["ip-src", "ip-dst", "ip-src/ip-dst"];
const MISP_DOMAIN_TYPES: &[&str] = &["domain", "hostname"];

/// Why a MISP read failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MispError {
    /// The source is not configured.
    #[error("MISP is not configured")]
    Unconfigured,
    /// The request arguments are not acceptable.
    #[error("MISP request is not acceptable")]
    Request,
    /// The API key could not be loaded.
    #[error("MISP API key could not be loaded")]
    Secret,
    /// The client could not be built.
    #[error("MISP client could not be built")]
    Client,
    /// The peer refused or failed the request.
    #[error("MISP request failed")]
    Upstream,
    /// The body is not a MISP attribute document.
    #[error("MISP response is not acceptable")]
    Body,
}

/// Filters for one MISP attribute search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MispQuery {
    /// Optional value match, as MISP restSearch `value`.
    pub value: Option<String>,
    /// Optional mapped kind. Applied after MISP types are reduced.
    pub kind: Option<IndicatorKind>,
    /// Maximum mapped rows to return.
    pub limit: usize,
}

/// One mapped indicator. Admission still happens at plan time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedIndicator {
    /// `ip`, `cidr`, or `domain`.
    pub kind: IndicatorKind,
    /// Raw MISP value.
    pub value: String,
    /// Origin token.
    pub source: String,
    /// Confidence from 0 to 100.
    pub confidence: u8,
    /// Unix seconds.
    pub first_seen: i64,
    /// Unix seconds.
    pub last_seen: i64,
}

/// One page of mapped indicators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MispPage {
    /// Mapped rows, in document order, after unknown types are skipped.
    pub indicators: Vec<MappedIndicator>,
    /// Attributes that were present and not mapped.
    pub skipped: usize,
    /// True when more mapped rows existed than `limit`.
    pub truncated: bool,
}

/// Read-only MISP search.
#[async_trait]
pub trait MispSource: Send + Sync {
    /// Search attributes. Does not write to MISP or to the feed.
    async fn search(&self, query: &MispQuery) -> Result<MispPage, MispError>;
}

/// HTTPS MISP client. One attempt per search; no retry.
pub struct MispClient {
    base_url: String,
    http: HttpClient,
    api_key: OutboundSecret,
}

impl MispClient {
    /// Load the named API key and build an HTTPS client.
    ///
    /// # Errors
    ///
    /// Returns [`MispError`] when the key, CA file, or client is not acceptable.
    pub fn new(config: &MispConfig) -> Result<Self, MispError> {
        let api_key = load_key(config)?;
        let mut extra_root_certificates = Vec::new();
        if let Some(path) = &config.ca_pem_path {
            let pem = std::fs::read_to_string(path).map_err(|_| MispError::Client)?;
            extra_root_certificates.push(pem);
        }
        let http = HttpClient::new(HttpClientConfig {
            request_timeout: REQUEST_TIMEOUT,
            max_concurrent_requests: MAX_CONCURRENT,
            max_queued_requests: MAX_QUEUED,
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: concat!("mecfeedmcp/", env!("CARGO_PKG_VERSION")).to_owned(),
            extra_root_certificates,
            ..HttpClientConfig::default()
        })
        .map_err(|_| MispError::Client)?;
        Ok(Self {
            base_url: config.base_url.clone(),
            http,
            api_key,
        })
    }
}

#[async_trait]
impl MispSource for MispClient {
    async fn search(&self, query: &MispQuery) -> Result<MispPage, MispError> {
        let body = search_body(query)?;
        let path = expand_path(SEARCH_PATH, &[]).map_err(|_| MispError::Request)?;
        let request = HttpRequest::with_base_and_path(Method::Post, &self.base_url, &path)
            .map_err(|_| MispError::Request)?
            .header("Accept", "application/json")
            .map_err(|_| MispError::Request)?
            .header("Content-Type", "application/json")
            .map_err(|_| MispError::Request)?
            .secret_header("Authorization", &self.api_key)
            .map_err(|_| MispError::Request)?
            .body(body);
        let response = self
            .http
            .send(request)
            .await
            .map_err(|_| MispError::Upstream)?;
        if response.status() >= 300 {
            return Err(MispError::Upstream);
        }
        let document: Value =
            serde_json::from_slice(response.body()).map_err(|_| MispError::Body)?;
        map_document(&document, query)
    }
}

fn load_key(config: &MispConfig) -> Result<OutboundSecret, MispError> {
    let limits = SecretLimits::default();
    if let Some(var) = &config.api_key_env {
        return load_from_env(var, limits).map_err(|_| MispError::Secret);
    }
    let path = config.api_key_file.as_deref().ok_or(MispError::Secret)?;
    load_from_file(Path::new(path), limits).map_err(|_| MispError::Secret)
}

fn search_body(query: &MispQuery) -> Result<Vec<u8>, MispError> {
    if query.limit == 0 {
        return Err(MispError::Request);
    }
    if let Some(value) = &query.value {
        check_query_value(value)?;
    }
    let types = misp_types(query.kind);
    let mut body = json!({
        "returnFormat": "json",
        "type": types,
        "to_ids": true,
        "deleted": false,
        "limit": query.limit,
        "page": 1,
    });
    if let Some(value) = &query.value {
        body["value"] = Value::String(value.clone());
    }
    serde_json::to_vec(&body).map_err(|_| MispError::Request)
}

fn check_query_value(value: &str) -> Result<(), MispError> {
    if value.is_empty() || value.len() > MAX_QUERY_BYTES || value.chars().any(|c| c.is_control()) {
        return Err(MispError::Request);
    }
    Ok(())
}

fn misp_types(kind: Option<IndicatorKind>) -> &'static [&'static str] {
    match kind {
        Some(IndicatorKind::Domain) => MISP_DOMAIN_TYPES,
        Some(IndicatorKind::Ip | IndicatorKind::Cidr) => MISP_IP_TYPES,
        None => &["ip-src", "ip-dst", "ip-src/ip-dst", "domain", "hostname"],
    }
}

/// Map a MISP restSearch document. Unknown types are skipped.
///
/// # Errors
///
/// Returns [`MispError::Body`] when the document is not an object that holds
/// attributes, or [`MispError::Request`] when `limit` is zero.
pub fn map_document(document: &Value, query: &MispQuery) -> Result<MispPage, MispError> {
    if query.limit == 0 {
        return Err(MispError::Request);
    }
    if let Some(value) = &query.value {
        check_query_value(value)?;
    }
    let mut skipped = 0;
    let mut indicators = Vec::new();
    let mut truncated = false;
    for attribute in attributes(document).ok_or(MispError::Body)? {
        match map_attribute(attribute) {
            Some(mapped) if kind_wanted(query.kind, mapped.kind) => {
                if indicators.len() >= query.limit {
                    truncated = true;
                    break;
                }
                indicators.push(mapped);
            }
            Some(_) | None => skipped += 1,
        }
    }
    Ok(MispPage {
        indicators,
        skipped,
        truncated,
    })
}

fn kind_wanted(filter: Option<IndicatorKind>, kind: IndicatorKind) -> bool {
    filter.is_none_or(|wanted| wanted == kind)
}

fn attributes(document: &Value) -> Option<Vec<&Value>> {
    let root = document.as_object()?;
    let payload = root.get("response").unwrap_or(document);
    if let Some(array) = payload.as_array() {
        return Some(array.iter().map(unwrap_attribute).collect());
    }
    let object = payload.as_object()?;
    let array = object.get("Attribute")?.as_array()?;
    Some(array.iter().map(unwrap_attribute).collect())
}

fn unwrap_attribute(value: &Value) -> &Value {
    value
        .get("Attribute")
        .filter(|inner| inner.is_object())
        .unwrap_or(value)
}

fn map_attribute(attribute: &Value) -> Option<MappedIndicator> {
    if truthy(attribute.get("deleted")) {
        return None;
    }
    if !truthy(attribute.get("to_ids")) {
        return None;
    }
    let misp_type = attribute.get("type")?.as_str()?;
    let value = attribute.get("value")?.as_str()?;
    if value.is_empty() || value.len() > MAX_QUERY_BYTES {
        return None;
    }
    let kind = map_type(misp_type, value)?;
    let timestamp = unix_seconds(attribute.get("timestamp"))?;
    let first_seen = unix_seconds(attribute.get("first_seen")).unwrap_or(timestamp);
    let last_seen = unix_seconds(attribute.get("last_seen")).unwrap_or(timestamp);
    Some(MappedIndicator {
        kind,
        value: value.to_string(),
        source: SOURCE.to_string(),
        confidence: DEFAULT_CONFIDENCE,
        first_seen,
        last_seen,
    })
}

fn map_type(misp_type: &str, value: &str) -> Option<IndicatorKind> {
    match misp_type {
        "ip-src" | "ip-dst" | "ip-src/ip-dst" => {
            if value.contains('/') {
                Some(IndicatorKind::Cidr)
            } else {
                Some(IndicatorKind::Ip)
            }
        }
        "domain" | "hostname" => Some(IndicatorKind::Domain),
        _ => None,
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        Some(Value::Number(n)) => n.as_u64() == Some(1) || n.as_i64() == Some(1),
        Some(Value::String(s)) => matches!(s.as_str(), "1" | "true" | "True"),
        _ => false,
    }
}

fn unix_seconds(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))
            .filter(|n| *n >= 0),
        Value::String(s) => s.parse::<i64>().ok().filter(|n| *n >= 0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use mecfeedmcp_core::IndicatorKind;
    use serde_json::json;

    use super::{MispError, MispQuery, map_document, map_type};

    fn query(kind: Option<IndicatorKind>, limit: usize) -> MispQuery {
        MispQuery {
            value: None,
            kind,
            limit,
        }
    }

    #[test]
    fn maps_ids_attributes_and_skips_the_rest() {
        let document = json!({
            "response": {
                "Attribute": [
                    {
                        "type": "ip-dst",
                        "value": "1.0.0.1",
                        "to_ids": true,
                        "deleted": false,
                        "timestamp": "1700000000"
                    },
                    {
                        "type": "ip-src",
                        "value": "203.0.113.0/24",
                        "to_ids": true,
                        "timestamp": 1700000000
                    },
                    {
                        "type": "domain",
                        "value": "evil.example",
                        "to_ids": "1",
                        "timestamp": "1700000000"
                    },
                    {
                        "type": "url",
                        "value": "https://evil.example/path",
                        "to_ids": true,
                        "timestamp": "1700000000"
                    },
                    {
                        "type": "ip-dst",
                        "value": "8.8.8.8",
                        "to_ids": false,
                        "timestamp": "1700000000"
                    },
                    {
                        "type": "hostname",
                        "value": "also.example",
                        "to_ids": true,
                        "deleted": true,
                        "timestamp": "1700000000"
                    }
                ]
            }
        });
        let page = map_document(&document, &query(None, 100)).expect("map");
        assert_eq!(page.indicators.len(), 3);
        assert_eq!(page.skipped, 3);
        assert!(!page.truncated);
        assert_eq!(page.indicators[0].kind, IndicatorKind::Ip);
        assert_eq!(page.indicators[0].value, "1.0.0.1");
        assert_eq!(page.indicators[0].source, "misp");
        assert_eq!(page.indicators[1].kind, IndicatorKind::Cidr);
        assert_eq!(page.indicators[2].kind, IndicatorKind::Domain);
    }

    #[test]
    fn kind_filter_is_applied_after_mapping() {
        let document = json!({
            "response": [{
                "Attribute": {
                    "type": "ip-src/ip-dst",
                    "value": "1.0.0.1",
                    "to_ids": true,
                    "timestamp": "1"
                }
            }]
        });
        let page = map_document(&document, &query(Some(IndicatorKind::Domain), 10)).expect("map");
        assert!(page.indicators.is_empty());
        assert_eq!(page.skipped, 1);
        let page = map_document(&document, &query(Some(IndicatorKind::Ip), 10)).expect("map");
        assert_eq!(page.indicators.len(), 1);
    }

    #[test]
    fn limit_truncates() {
        let document = json!({
            "Attribute": [
                {"type": "ip-dst", "value": "1.0.0.1", "to_ids": true, "timestamp": "1"},
                {"type": "ip-dst", "value": "1.0.0.2", "to_ids": true, "timestamp": "1"}
            ]
        });
        let page = map_document(&document, &query(None, 1)).expect("map");
        assert_eq!(page.indicators.len(), 1);
        assert!(page.truncated);
    }

    #[test]
    fn malformed_document_fails_closed() {
        let error = map_document(&json!([]), &query(None, 10)).expect_err("array");
        assert_eq!(error, MispError::Body);
        let error = map_document(&json!({"response": "nope"}), &query(None, 10)).expect_err("text");
        assert_eq!(error, MispError::Body);
        let error = map_document(&json!({"response": {"Attribute": []}}), &query(None, 0))
            .expect_err("limit");
        assert_eq!(error, MispError::Request);
    }

    #[test]
    fn composite_types_are_not_addresses() {
        assert_eq!(map_type("domain|ip", "evil.example|1.0.0.1"), None);
        assert_eq!(map_type("ip-dst|port", "1.0.0.1|443"), None);
        assert_eq!(map_type("url", "https://evil.example"), None);
    }
}
