//! Special-purpose range checks. These are the hard floor: a later policy
//! may only be stricter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Broadest IPv4 prefix a feed may carry. A shorter prefix is rejected.
pub const MIN_IPV4_PREFIX_LEN: u8 = 8;
/// Broadest IPv6 prefix a feed may carry. A shorter prefix is rejected.
pub const MIN_IPV6_PREFIX_LEN: u8 = 19;

// IANA IPv4 Special-Purpose Address Registry.
const RESERVED_IPV4: [Ipv4Net; 15] = [
    Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 2, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 88, 99, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15),
    Ipv4Net::new_assert(Ipv4Addr::new(198, 51, 100, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(203, 0, 113, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
    Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4),
];

// IANA IPv6 Special-Purpose Address Registry.
const RESERVED_IPV6: [Ipv6Net; 12] = [
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128),
    Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128),
    Ipv6Net::new_assert(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
    Ipv6Net::new_assert(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
    Ipv6Net::new_assert(Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    Ipv6Net::new_assert(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
    Ipv6Net::new_assert(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

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
    /// Special-purpose address space, or a prefix broader than the minimum length.
    #[error("indicator is in a reserved range: {0}")]
    Reserved(String),
    /// Empty or whitespace-only value.
    #[error("indicator value is empty")]
    Empty,
}

/// Parse and reject special-purpose ranges. Fail closed: ambiguity is an error.
///
/// Addresses and prefixes in the IANA special-purpose registries are rejected.
/// A prefix that contains one of those ranges is rejected, as is a prefix
/// broader than `/8` (IPv4) or `/19` (IPv6). IPv4-mapped IPv6 addresses are
/// rejected with that mapped prefix.
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
            if ip_in_reserved(ip) {
                return Err(ValidationError::Reserved(value.to_string()));
            }
        }
        IndicatorKind::Cidr => {
            let net: IpNet = value.parse().map_err(|_| ValidationError::Unparseable {
                kind: IndicatorKind::Cidr,
                value: value.to_string(),
            })?;
            // Host bits set is ambiguity; fail closed before the range check.
            if net.network() != net.addr() {
                return Err(ValidationError::Unparseable {
                    kind: IndicatorKind::Cidr,
                    value: value.to_string(),
                });
            }
            if prefix_too_broad(net) || prefix_overlaps_reserved(net) {
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

/// IPv4-mapped addresses are special-purpose (`::ffff:0:0/96`), so they are
/// rejected here rather than rewritten into an IPv4 address.
fn ip_in_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => RESERVED_IPV4.iter().any(|net| net.contains(&v4)),
        IpAddr::V6(v6) => RESERVED_IPV6.iter().any(|net| net.contains(&v6)),
    }
}

fn prefix_too_broad(net: IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() < MIN_IPV4_PREFIX_LEN,
        IpNet::V6(v6) => v6.prefix_len() < MIN_IPV6_PREFIX_LEN,
    }
}

fn prefix_overlaps_reserved(net: IpNet) -> bool {
    match net {
        IpNet::V4(v4) => RESERVED_IPV4
            .iter()
            .any(|reserved| reserved.contains(&v4) || v4.contains(reserved)),
        IpNet::V6(v6) => RESERVED_IPV6
            .iter()
            .any(|reserved| reserved.contains(&v6) || v6.contains(reserved)),
    }
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

    fn assert_reserved(indicator: &Indicator) {
        let err = validate_indicator(indicator).expect_err(indicator.value.as_str());
        assert!(
            matches!(err, ValidationError::Reserved(_)),
            "{}: {err:?}",
            indicator.value
        );
    }

    #[test]
    fn special_purpose_addresses_are_rejected() {
        for value in [
            "0.1.2.3",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert_reserved(&ip(value));
        }
    }

    #[test]
    fn special_purpose_and_overbroad_prefixes_are_rejected() {
        // `172.0.0.0/8` is exactly the minimum IPv4 length, so only overlap
        // with a special-purpose range rejects it. `8.0.0.0/7` and
        // `3000::/18` do not overlap a reserved range; length rejects them.
        for value in [
            "128.0.0.0/1",
            "172.0.0.0/8",
            "8.0.0.0/5",
            "192.0.0.0/2",
            "8.0.0.0/7",
            "10.0.0.0/8",
            "10.1.0.0/16",
            "203.0.113.0/24",
            "::ffff:0:0/96",
            "2001:db8::/32",
            "3000::/18",
        ] {
            assert_reserved(&cidr(value));
        }
    }

    #[test]
    fn boundary_public_prefixes_are_accepted() {
        for value in ["1.1.1.1", "8.0.0.0/8", "172.15.0.0/16", "192.0.1.0/24"] {
            validate_indicator(&ip_or_cidr(value)).expect(value);
        }
        for value in ["2001:4860:4860::8888", "2606:4700::/32", "2000::/19"] {
            validate_indicator(&ip_or_cidr(value)).expect(value);
        }
    }

    fn ip_or_cidr(value: &str) -> Indicator {
        if value.contains('/') {
            cidr(value)
        } else {
            ip(value)
        }
    }
}
