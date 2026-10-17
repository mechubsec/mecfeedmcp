//! Indicator model, validators, and feed versioning for `mecfeedmcp`.
//!
//! Pure logic: no I/O. Source readers, change-set lifecycle, and the feed
//! HTTP server live in the other workspace crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Kind of indicator a feed may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// A single IPv4 or IPv6 address.
    Ip,
    /// A CIDR prefix.
    Cidr,
    /// A DNS name.
    Domain,
}

/// One indicator proposed for a feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    /// Discriminator.
    pub kind: IndicatorKind,
    /// Canonical text form: dotted IP, CIDR, or domain.
    pub value: String,
}

/// Why an indicator was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// The value could not be parsed as the declared kind.
    #[error("unparseable {kind:?} indicator: {value}")]
    Unparseable {
        /// Declared kind.
        kind: IndicatorKind,
        /// Raw value.
        value: String,
    },
    /// Private, loopback, link-local, or otherwise reserved address space.
    #[error("indicator is in a reserved range: {0}")]
    Reserved(String),
    /// Empty or whitespace-only value.
    #[error("indicator value is empty")]
    Empty,
}

/// Parse and reject reserved ranges. Fail closed: ambiguity is an error.
///
/// Domain validation is syntactic only at this layer (non-empty, no spaces).
/// Allowlists, expiry, and per-change caps belong to a later phase.
pub fn validate_indicator(indicator: &Indicator) -> Result<(), ValidationError> {
    let value = indicator.value.trim();
    if value.is_empty() {
        return Err(ValidationError::Empty);
    }
    match indicator.kind {
        IndicatorKind::Ip => {
            let ip: IpAddr = value.parse().map_err(|_| ValidationError::Unparseable {
                kind: IndicatorKind::Ip,
                value: value.to_string(),
            })?;
            if is_reserved_ip(ip) {
                return Err(ValidationError::Reserved(value.to_string()));
            }
        }
        IndicatorKind::Cidr => {
            let net: IpNet = value.parse().map_err(|_| ValidationError::Unparseable {
                kind: IndicatorKind::Cidr,
                value: value.to_string(),
            })?;
            if is_reserved_ip(net.addr()) || net.network() != net.addr() {
                // Uncanonical CIDR (host bits set) is ambiguity; fail closed.
                if net.network() != net.addr() {
                    return Err(ValidationError::Unparseable {
                        kind: IndicatorKind::Cidr,
                        value: value.to_string(),
                    });
                }
                return Err(ValidationError::Reserved(value.to_string()));
            }
        }
        IndicatorKind::Domain => {
            if value.contains(char::is_whitespace) || value.contains('/') {
                return Err(ValidationError::Unparseable {
                    kind: IndicatorKind::Domain,
                    value: value.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

/// Crate version from the workspace package.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> Indicator {
        Indicator {
            kind: IndicatorKind::Ip,
            value: value.to_string(),
        }
    }

    fn cidr(value: &str) -> Indicator {
        Indicator {
            kind: IndicatorKind::Cidr,
            value: value.to_string(),
        }
    }

    #[test]
    fn public_unicast_ip_is_accepted() {
        validate_indicator(&ip("8.8.8.8")).expect("public unicast");
    }

    #[test]
    fn documentation_net_is_rejected() {
        // 203.0.113.0/24 is TEST-NET-3 (documentation). Fail closed.
        let err = validate_indicator(&ip("203.0.113.10")).expect_err("documentation net");
        assert!(matches!(err, ValidationError::Reserved(_)));
    }

    #[test]
    fn rfc1918_is_rejected() {
        for value in ["10.0.0.1", "192.168.1.1", "172.16.0.4"] {
            let err = validate_indicator(&ip(value)).expect_err("rfc1918");
            assert!(matches!(err, ValidationError::Reserved(_)), "{value}");
        }
    }

    #[test]
    fn loopback_is_rejected() {
        let err = validate_indicator(&ip("127.0.0.1")).expect_err("loopback");
        assert!(matches!(err, ValidationError::Reserved(_)));
    }

    #[test]
    fn public_cidr_is_accepted() {
        validate_indicator(&cidr("8.8.8.0/24")).expect("public unicast prefix");
    }

    #[test]
    fn uncanonical_cidr_is_rejected() {
        let err = validate_indicator(&cidr("8.8.8.8/24")).expect_err("uncanonical cidr");
        assert!(matches!(err, ValidationError::Unparseable { .. }));
    }

    #[test]
    fn empty_is_rejected() {
        let err = validate_indicator(&ip("  ")).expect_err("empty");
        assert!(matches!(err, ValidationError::Empty));
    }

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }
}
