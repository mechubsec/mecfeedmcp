//! Operator feed config. Secrets are named, never inlined.

use std::path::{Path, PathBuf};

use ipnet::IpNet;
use mecfeedmcp_core::{Limits, Policy, PolicyError};
use serde::Deserialize;
use thiserror::Error;

fn default_snapshot_dir() -> PathBuf {
    PathBuf::from("/var/lib/mecfeedmcp/snapshots")
}

/// Operator-authored feed.json. No secrets.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    /// Config schema version. Must be 1.
    pub version: u32,
    /// Tenant name recorded on each change set.
    pub tenant: String,
    /// Absolute path to the change-set state file.
    #[serde(default)]
    pub changeset_state_file: Option<PathBuf>,
    /// Absolute directory the MCP server writes snapshots into.
    #[serde(default = "default_snapshot_dir")]
    pub snapshot_dir: PathBuf,
    /// How long an approval stays valid, in seconds.
    #[serde(default)]
    pub approval_ttl_secs: Option<u64>,
    /// Prefixes the operator owns. Overlap is refused at admission.
    #[serde(default)]
    pub own_prefixes: Vec<String>,
    /// Prefixes that must never enter the feed.
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    /// Domain suffixes that must never enter the feed.
    #[serde(default)]
    pub allow_domain_suffixes: Vec<String>,
    /// Optional read-only MISP source.
    #[serde(default)]
    pub misp: Option<MispConfig>,
}

/// MISP source. The API key is a file or environment reference.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MispConfig {
    /// Origin only: `https://host` or `https://host:port`.
    pub base_url: String,
    /// Environment variable holding the API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Absolute file holding the API key. Mutually exclusive with the env form.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// PEM trust anchor, for a MISP behind a private CA.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
}

/// Why feed.json could not be used.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The file is not JSON that matches this schema.
    #[error("feed.json is not acceptable")]
    Syntax,
    /// The schema version is not 1.
    #[error("feed.json version must be 1")]
    Version,
    /// The tenant is empty.
    #[error("feed.json tenant must be a non-empty string")]
    Tenant,
    /// A prefix on the operator lists is not a CIDR.
    #[error("feed.json prefix is not acceptable")]
    Prefix,
    /// An allowlist suffix is not a canonical domain.
    #[error("feed.json domain suffix is not acceptable")]
    Suffix,
    /// The MISP origin is not `https://host` or `https://host:port`.
    #[error("MISP base URL is not an https origin")]
    MispUrl,
    /// The MISP source names both key locations, or neither.
    #[error("MISP API key must be exactly one of api_key_env or api_key_file")]
    MispKey,
    /// The MISP key file path is not absolute.
    #[error("MISP API key file must be an absolute path")]
    MispKeyPath,
    /// The private-CA file path is not absolute.
    #[error("MISP CA file must be an absolute path")]
    MispCaPath,
}

impl FeedConfig {
    /// Parse operator config. Inline secrets are unknown fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the JSON or a field is not acceptable.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(text).map_err(|_| ConfigError::Syntax)?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Version);
        }
        if self.tenant.is_empty() {
            return Err(ConfigError::Tenant);
        }
        if let Some(misp) = &self.misp {
            misp.check()?;
        }
        Ok(())
    }

    /// Admission policy from the operator lists. Limits stay at the crate default.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a prefix or suffix is not acceptable.
    pub fn policy(&self) -> Result<Policy, ConfigError> {
        let own = parse_cidrs(&self.own_prefixes)?;
        let allow = parse_cidrs(&self.allow_cidrs)?;
        Policy::try_new(
            own,
            allow,
            self.allow_domain_suffixes.iter().map(String::as_str),
            Limits::default(),
        )
        .map_err(|error| match error {
            PolicyError::Suffix => ConfigError::Suffix,
            _ => ConfigError::Prefix,
        })
    }

    /// Absolute path of the MISP key file, when that form is used.
    #[must_use]
    pub fn misp_key_file(&self) -> Option<&Path> {
        self.misp
            .as_ref()
            .and_then(|misp| misp.api_key_file.as_deref())
    }
}

impl MispConfig {
    fn check(&self) -> Result<(), ConfigError> {
        check_https_origin(&self.base_url)?;
        match (&self.api_key_env, &self.api_key_file) {
            (Some(name), None) => {
                if !valid_env_name(name) {
                    return Err(ConfigError::MispKey);
                }
            }
            (None, Some(path)) => {
                if !path.is_absolute() {
                    return Err(ConfigError::MispKeyPath);
                }
            }
            _ => return Err(ConfigError::MispKey),
        }
        if let Some(path) = &self.ca_pem_path
            && !path.is_absolute()
        {
            return Err(ConfigError::MispCaPath);
        }
        Ok(())
    }
}

fn parse_cidrs(values: &[String]) -> Result<Vec<IpNet>, ConfigError> {
    values
        .iter()
        .map(|value| value.parse().map_err(|_| ConfigError::Prefix))
        .collect()
}

fn check_https_origin(url: &str) -> Result<(), ConfigError> {
    let rest = url.strip_prefix("https://").ok_or(ConfigError::MispUrl)?;
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
    {
        return Err(ConfigError::MispUrl);
    }
    Ok(())
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, FeedConfig};

    fn parse(body: &str) -> Result<FeedConfig, ConfigError> {
        FeedConfig::parse(body)
    }

    #[test]
    fn example_shape_loads() {
        let config = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "changeset_state_file": "/var/lib/mecfeedmcp/changeset-state.json",
                "snapshot_dir": "/var/lib/mecfeedmcp/snapshots",
                "approval_ttl_secs": 3600,
                "own_prefixes": [],
                "allow_cidrs": [],
                "allow_domain_suffixes": []
            }"#,
        )
        .expect("example");
        assert!(config.misp.is_none());
        let policy = config.policy().expect("policy");
        assert_eq!(policy.max_entries(), 100);
    }

    #[test]
    fn operator_lists_reach_policy() {
        let config = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "own_prefixes": ["203.0.113.0/24"],
                "allow_cidrs": ["8.8.8.8/32"],
                "allow_domain_suffixes": ["acme.co.uk"]
            }"#,
        )
        .expect("config");
        config.policy().expect("policy");
    }

    #[test]
    fn inline_misp_key_is_unknown() {
        let error = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "misp": {
                    "base_url": "https://misp.example.invalid",
                    "api_key": "inline"
                }
            }"#,
        )
        .expect_err("inline");
        assert_eq!(error, ConfigError::Syntax);
    }

    #[test]
    fn misp_needs_https_origin_and_one_key_ref() {
        let error = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "misp": {
                    "base_url": "http://misp.example.invalid",
                    "api_key_env": "MISP_API_KEY"
                }
            }"#,
        )
        .expect_err("http");
        assert_eq!(error, ConfigError::MispUrl);

        let error = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "misp": {
                    "base_url": "https://misp.example.invalid/path",
                    "api_key_env": "MISP_API_KEY"
                }
            }"#,
        )
        .expect_err("path");
        assert_eq!(error, ConfigError::MispUrl);

        let error = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "misp": {
                    "base_url": "https://misp.example.invalid"
                }
            }"#,
        )
        .expect_err("no key");
        assert_eq!(error, ConfigError::MispKey);

        parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "misp": {
                    "base_url": "https://misp.example.invalid:8443",
                    "api_key_env": "MISP_API_KEY"
                }
            }"#,
        )
        .expect("https origin with port");
    }

    #[test]
    fn relative_key_file_is_refused() {
        let error = parse(
            r#"{
                "version": 1,
                "tenant": "lab",
                "misp": {
                    "base_url": "https://misp.example.invalid",
                    "api_key_file": "misp.key"
                }
            }"#,
        )
        .expect_err("relative");
        assert_eq!(error, ConfigError::MispKeyPath);
    }
}
