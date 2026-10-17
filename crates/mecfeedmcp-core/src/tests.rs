use ipnet::IpNet;
use sha2::{Digest, Sha256};

use crate::model::{Proposal, ProposedEntry};
use crate::policy::{AdmitError, EntryError, FeedIndicator, Limits, Policy, PolicyError};
use crate::range::IndicatorKind;
use crate::render::{FeedFormat, RenderError, render_feed};
use crate::version::{FeedVersions, SweepOutcome, VersionError, canonical_content};

const NOW: i64 = 1_700_000_000;
const WEEK: i64 = 7 * 24 * 60 * 60;

fn net(value: &str) -> IpNet {
    value.parse().expect(value)
}

fn limits_broad() -> Limits {
    Limits {
        permit_explicit_broad: true,
        ..Limits::default()
    }
}

fn policy(own: &[&str], allow: &[&str], suffixes: &[&str], limits: Limits) -> Policy {
    Policy::try_new(
        own.iter().copied().map(net).collect(),
        allow.iter().copied().map(net).collect(),
        suffixes.iter().copied(),
        limits,
    )
    .expect("policy")
}

fn empty_policy() -> Policy {
    policy(&[], &[], &[], Limits::default())
}

fn entry(kind: IndicatorKind, value: &str) -> ProposedEntry {
    ProposedEntry {
        kind,
        value: value.to_string(),
        source: "lab".to_string(),
        confidence: 50,
        first_seen: NOW,
        last_seen: NOW,
        expires_at: Some(NOW + WEEK),
        allow_broad_prefix: false,
    }
}

fn proposal(entries: Vec<ProposedEntry>) -> Proposal {
    Proposal { entries }
}

fn publish_one(
    feed: &mut FeedVersions,
    kind: IndicatorKind,
    value: &str,
) -> Result<(), VersionError> {
    feed.publish(&proposal(vec![entry(kind, value)]), NOW)
        .map(|_| ())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn version_is_nonempty() {
    assert!(!crate::version().is_empty());
}

#[test]
fn default_limits_match_the_phase_contract() {
    let limits = Limits::default();
    assert_eq!(limits.max_entries, 100);
    assert_eq!(limits.default_ttl_secs, WEEK);
    assert_eq!(limits.max_ttl_secs, 30 * 24 * 60 * 60);
    assert_eq!(limits.min_ipv4_prefix, 24);
    assert_eq!(limits.min_ipv6_prefix, 48);
    assert!(!limits.permit_explicit_broad);
}

#[test]
fn invalid_policy_is_rejected() {
    let err = Policy::try_new(vec![], vec![], ["com"], Limits::default()).expect_err("suffix");
    assert_eq!(err, PolicyError::Suffix);
    let err = Policy::try_new(
        vec![],
        vec![],
        Vec::<&str>::new(),
        Limits {
            max_entries: 0,
            ..Limits::default()
        },
    )
    .expect_err("cap");
    assert_eq!(err, PolicyError::EntryCap);
    let err = Policy::try_new(
        vec![],
        vec![],
        Vec::<&str>::new(),
        Limits {
            min_ipv4_prefix: 16,
            ..Limits::default()
        },
    )
    .expect_err("prefix");
    assert_eq!(err, PolicyError::PrefixMinimum);
}

#[test]
fn omitted_expiry_defaults_to_seven_days_and_thirty_is_the_max() {
    let mut feed = FeedVersions::open(empty_policy());
    let mut proposed = entry(IndicatorKind::Ip, "1.1.1.1");
    proposed.expires_at = None;
    feed.publish(&proposal(vec![proposed]), NOW)
        .expect("default ttl");
    assert_eq!(
        feed.latest().expect("snap").entries()[0].expires_at(),
        NOW + WEEK
    );

    let mut too_long = entry(IndicatorKind::Ip, "1.0.0.1");
    too_long.expires_at = Some(NOW + 30 * 24 * 60 * 60 + 1);
    let err = feed
        .publish(&proposal(vec![too_long]), NOW)
        .expect_err("max ttl");
    assert!(matches!(
        err,
        VersionError::Admit(AdmitError::Entry {
            reason: EntryError::Ttl { .. },
            ..
        })
    ));
    assert_eq!(feed.latest().expect("snap").entries().len(), 1);
}

#[test]
fn forbidden_indicators_never_reach_a_rendered_feed() {
    let mut feed = FeedVersions::open(policy(
        &["8.8.8.0/24", "2606:4700:4700::/48"],
        &["9.9.9.0/24"],
        &["partner.test"],
        Limits::default(),
    ));
    let forbidden = [
        (IndicatorKind::Ip, "10.0.0.1"),
        (IndicatorKind::Ip, "192.168.1.1"),
        (IndicatorKind::Ip, "172.16.0.4"),
        (IndicatorKind::Ip, "127.0.0.1"),
        (IndicatorKind::Ip, "100.64.0.1"),
        (IndicatorKind::Ip, "169.254.1.1"),
        (IndicatorKind::Ip, "192.0.2.1"),
        (IndicatorKind::Ip, "198.51.100.1"),
        (IndicatorKind::Ip, "203.0.113.10"),
        (IndicatorKind::Ip, "224.0.0.1"),
        (IndicatorKind::Ip, "240.0.0.1"),
        (IndicatorKind::Ip, "255.255.255.255"),
        (IndicatorKind::Ip, "::"),
        (IndicatorKind::Ip, "::1"),
        (IndicatorKind::Ip, "fc00::1"),
        (IndicatorKind::Ip, "fe80::1"),
        (IndicatorKind::Ip, "ff02::1"),
        (IndicatorKind::Ip, "::ffff:8.8.8.8"),
        (IndicatorKind::Ip, "8.8.8.8"),
        (IndicatorKind::Ip, "9.9.9.9"),
        (IndicatorKind::Ip, "2606:4700:4700::1111"),
        (IndicatorKind::Cidr, "10.1.0.0/16"),
        (IndicatorKind::Cidr, "8.8.8.0/24"),
        (IndicatorKind::Cidr, "9.9.9.0/24"),
        (IndicatorKind::Cidr, "1.2.0.0/16"),
        (IndicatorKind::Domain, "partner.test"),
        (IndicatorKind::Domain, "a.partner.test"),
        (IndicatorKind::Domain, "A.Partner.TEST"),
    ];
    for (kind, value) in forbidden {
        assert!(publish_one(&mut feed, kind, value).is_err(), "{value}");
    }
    assert!(feed.latest().is_none());

    let mixed = proposal(vec![
        entry(IndicatorKind::Ip, "1.1.1.1"),
        entry(IndicatorKind::Ip, "10.0.0.1"),
    ]);
    assert!(feed.publish(&mixed, NOW).is_err());
    assert!(feed.latest().is_none());

    feed.publish(
        &proposal(vec![
            entry(IndicatorKind::Ip, "1.1.1.1"),
            entry(IndicatorKind::Domain, "blocked.example"),
        ]),
        NOW,
    )
    .expect("admit");

    for format in [
        FeedFormat::PanosEdl,
        FeedFormat::JunosDynamicAddress,
        FeedFormat::FortigateThreatFeed,
        FeedFormat::OpnsenseUrlTable,
    ] {
        for kind in [
            IndicatorKind::Ip,
            IndicatorKind::Cidr,
            IndicatorKind::Domain,
        ] {
            match feed.render(format, kind, NOW) {
                Ok(text) => {
                    if kind == IndicatorKind::Ip {
                        assert!(text.contains("1.1.1.1"), "{format:?} {kind:?}");
                    }
                    for (_, value) in forbidden {
                        assert!(
                            !text.contains(value),
                            "{format:?} {kind:?} contained {value}"
                        );
                    }
                    assert!(
                        !text.contains("blocked.example") || kind == IndicatorKind::Domain,
                        "{format:?} {kind:?} mixed kinds"
                    );
                }
                Err(RenderError::UnsupportedKind { .. }) => {
                    assert_eq!(format, FeedFormat::JunosDynamicAddress);
                    assert_eq!(kind, IndicatorKind::Domain);
                }
                Err(err) => panic!("{format:?} {kind:?}: {err}"),
            }
        }
    }
}

#[test]
fn explicit_broad_prefix_stops_at_the_hard_floor() {
    let mut strict = FeedVersions::open(empty_policy());
    assert!(publish_one(&mut strict, IndicatorKind::Cidr, "8.0.0.0/8").is_err());

    let mut allowed = FeedVersions::open(policy(&[], &[], &[], limits_broad()));
    let mut broad = entry(IndicatorKind::Cidr, "8.0.0.0/8");
    broad.allow_broad_prefix = true;
    allowed
        .publish(&proposal(vec![broad]), NOW)
        .expect("explicit");
    assert_eq!(
        allowed.latest().expect("snap").entries()[0].value(),
        "8.0.0.0/8"
    );

    let mut still_broad = entry(IndicatorKind::Cidr, "8.0.0.0/7");
    still_broad.allow_broad_prefix = true;
    assert!(allowed.publish(&proposal(vec![still_broad]), NOW).is_err());
}

#[test]
fn duplicate_live_entry_is_rejected_and_expired_entry_can_be_replaced() {
    let mut feed = FeedVersions::open(empty_policy());
    publish_one(&mut feed, IndicatorKind::Ip, "1.1.1.1").expect("first");
    assert!(publish_one(&mut feed, IndicatorKind::Ip, "1.1.1.1").is_err());
    assert_eq!(feed.latest().expect("snap").manifest().number(), 1);

    let mut short = entry(IndicatorKind::Ip, "1.0.0.1");
    short.expires_at = Some(NOW + 10);
    feed.publish(&proposal(vec![short]), NOW).expect("short");
    let later = NOW + 11;
    let mut renewed = entry(IndicatorKind::Ip, "1.0.0.1");
    renewed.first_seen = later;
    renewed.last_seen = later;
    renewed.expires_at = Some(later + WEEK);
    feed.publish(&proposal(vec![renewed]), later)
        .expect("replace");
    let values: Vec<_> = feed
        .latest()
        .expect("snap")
        .entries()
        .iter()
        .map(|e| e.value())
        .collect();
    assert_eq!(
        values.iter().filter(|value| **value == "1.0.0.1").count(),
        1
    );
    assert!(
        feed.latest()
            .expect("snap")
            .entries()
            .iter()
            .any(|e| e.value() == "1.0.0.1" && e.expires_at() == later + WEEK)
    );
}

#[test]
fn rollback_republishes_the_previous_snapshot_and_leaves_it_immutable() {
    let mut feed = FeedVersions::open(empty_policy());
    publish_one(&mut feed, IndicatorKind::Ip, "1.1.1.1").expect("v1");
    let v1_digest = feed
        .latest()
        .expect("v1")
        .manifest()
        .content_digest()
        .to_string();
    publish_one(&mut feed, IndicatorKind::Ip, "1.0.0.1").expect("v2");
    feed.rollback_to(1, 2, NOW).expect("rollback");
    assert_eq!(feed.latest().expect("v3").manifest().number(), 3);
    assert_eq!(feed.latest().expect("v3").manifest().parent(), Some(2));
    assert_eq!(
        feed.latest().expect("v3").manifest().content_digest(),
        v1_digest
    );
    assert_ne!(
        feed.latest().expect("v3").manifest().digest(),
        feed.get(1).expect("v1").manifest().digest()
    );
    assert_eq!(
        feed.get(1).expect("v1").manifest().content_digest(),
        v1_digest
    );
    assert_eq!(feed.get(1).expect("v1").entries().len(), 1);
    let retry = feed.rollback_to(1, 2, NOW).expect_err("stale retry");
    assert_eq!(
        retry,
        VersionError::Stale {
            expected: 2,
            latest: 3
        }
    );
    assert_eq!(feed.latest().expect("v3").manifest().number(), 3);
    let err = FeedVersions::open(empty_policy())
        .rollback_to(1, 1, NOW)
        .expect_err("empty");
    assert_eq!(err, VersionError::Empty);
}

#[test]
fn rollback_refuses_unknown_or_current_targets_and_screens_restored_rows() {
    let mut feed = FeedVersions::open(empty_policy());
    publish_one(&mut feed, IndicatorKind::Ip, "1.1.1.1").expect("v1");
    publish_one(&mut feed, IndicatorKind::Ip, "1.0.0.1").expect("v2");
    assert_eq!(
        feed.rollback_to(2, 2, NOW).expect_err("current"),
        VersionError::NothingToRollBack
    );
    assert_eq!(
        feed.rollback_to(9, 2, NOW).expect_err("unknown"),
        VersionError::NothingToRollBack
    );
    feed.update_policy(policy(&["1.1.1.0/24"], &[], &[], Limits::default()));
    let err = feed.rollback_to(1, 2, NOW).expect_err("restored row");
    assert!(matches!(err, VersionError::Restored { .. }));
    assert_eq!(feed.latest().expect("v2").manifest().number(), 2);
}

#[test]
fn address_lookalikes_are_not_admitted_as_domains() {
    let mut feed = FeedVersions::open(policy(&["8.8.8.0/24"], &[], &[], Limits::default()));
    for value in [
        "10.0.0.01",
        "127.1",
        "0x0a.0.0.1",
        "192.168.1",
        "8.8.8.010",
        "1.2.3",
    ] {
        assert!(
            publish_one(&mut feed, IndicatorKind::Domain, value).is_err(),
            "{value}"
        );
    }
    assert!(feed.latest().is_none());
    publish_one(&mut feed, IndicatorKind::Domain, "bad.example").expect("name");
    publish_one(&mut feed, IndicatorKind::Domain, "bad.xn--p1ai").expect("punycode tld");
}

#[test]
fn two_label_public_suffixes_are_sorted_and_unique() {
    let list = crate::two_label_public_suffixes::TWO_LABEL_PUBLIC_SUFFIXES;
    assert!(list.windows(2).all(|pair| pair[0] < pair[1]));
    for suffix in ["co.uk", "com.au", "github.io", "ac.uk"] {
        assert!(list.binary_search(&suffix).is_ok(), "{suffix}");
    }
}

#[test]
fn public_suffix_names_need_an_extra_label() {
    let mut feed = FeedVersions::open(empty_policy());
    for value in [
        "co.uk",
        "evil.co.uk",
        "github.io",
        "pages.github.io",
        "com.au",
        "shop.com.au",
    ] {
        let err = publish_one(&mut feed, IndicatorKind::Domain, value).expect_err(value);
        assert!(
            matches!(
                err,
                VersionError::Admit(AdmitError::Entry {
                    reason: EntryError::BroadDomain,
                    ..
                })
            ),
            "{value}: {err:?}"
        );
    }
    publish_one(&mut feed, IndicatorKind::Domain, "malware.evil.co.uk").expect("co.uk extra");
    publish_one(&mut feed, IndicatorKind::Domain, "evil.pages.github.io").expect("github.io extra");
    publish_one(&mut feed, IndicatorKind::Domain, "blocked.example").expect("single-label tld");
    publish_one(&mut feed, IndicatorKind::Domain, "malware.example.com").expect("com extra");
}

#[test]
fn publish_drops_expired_rows_and_rescreens_live_rows() {
    let mut feed = FeedVersions::open(empty_policy());
    let mut short = entry(IndicatorKind::Ip, "1.0.0.1");
    short.expires_at = Some(NOW + 10);
    feed.publish(&proposal(vec![short]), NOW).expect("v1");
    feed.publish(
        &proposal(vec![entry(IndicatorKind::Ip, "1.1.1.1")]),
        NOW + 20,
    )
    .expect("v2");
    let values: Vec<_> = feed
        .latest()
        .expect("v2")
        .entries()
        .iter()
        .map(|e| e.value().to_string())
        .collect();
    assert_eq!(values, ["1.1.1.1"]);

    feed.update_policy(policy(&["1.1.1.0/24"], &[], &[], Limits::default()));
    let err = feed
        .publish(
            &proposal(vec![entry(IndicatorKind::Ip, "1.0.0.1")]),
            NOW + 20,
        )
        .expect_err("live row now violates policy");
    assert!(matches!(err, VersionError::Admit(AdmitError::Live { .. })));
    assert_eq!(feed.latest().expect("v2").manifest().number(), 2);
}

#[test]
fn error_text_escapes_and_truncates_untrusted_values() {
    let long = format!("a\n\u{1b}[31m{}", "x".repeat(200));
    let err = crate::validate_indicator(&crate::Indicator {
        kind: IndicatorKind::Domain,
        value: long,
    })
    .expect_err("whitespace");
    let text = err.to_string();
    assert!(!text.contains('\n') && !text.contains('\u{1b}'));
    assert!(text.len() < 200, "{}", text.len());
}

mod props {
    use super::*;
    use proptest::prelude::*;

    fn feed() -> FeedVersions {
        FeedVersions::open(policy(
            &["8.8.8.0/24", "2606:4700:4700::/48"],
            &["9.9.9.0/24"],
            &["partner.test"],
            Limits::default(),
        ))
    }

    proptest! {
        #[test]
        fn reserved_own_and_allowlisted_ips_never_reach_a_feed(
            a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>(), pick in 0usize..6,
        ) {
            let ip = match pick {
                0 => format!("10.{b}.{c}.{d}"),
                1 => format!("192.168.{c}.{d}"),
                2 => format!("127.{b}.{c}.{d}"),
                3 => format!("8.8.8.{d}"),
                4 => format!("9.9.9.{d}"),
                _ => format!("{}.{b}.{c}.{d}", 224 + (a % 32)),
            };
            let mut feed = feed();
            prop_assert!(publish_one(&mut feed, IndicatorKind::Ip, &ip).is_err(), "{ip}");
        }

        #[test]
        fn lookalike_strings_never_reach_a_feed(
            parts in proptest::collection::vec("(0x[0-9a-f]{1,2}|0[0-7]{1,3}|[0-9]{1,3})", 1..5),
            kind in prop_oneof![
                Just(IndicatorKind::Ip), Just(IndicatorKind::Cidr), Just(IndicatorKind::Domain)
            ],
        ) {
            let value = parts.join(".");
            prop_assume!(value.parse::<std::net::IpAddr>().is_err());
            let mut feed = feed();
            prop_assert!(publish_one(&mut feed, kind, &value).is_err(), "{kind:?} {value}");
        }

        #[test]
        fn prefixes_inside_blocked_ranges_never_reach_a_feed(
            host in any::<u8>(),
            len in 8u8..=32,
            pick in 0usize..10,
        ) {
            let value = blocked_v4_prefix(pick, host, len);
            let mut feed = feed();
            prop_assert!(
                publish_one(&mut feed, IndicatorKind::Cidr, &value).is_err(),
                "{value}"
            );
        }

        #[test]
        fn ipv6_prefixes_inside_blocked_ranges_never_reach_a_feed(
            host in any::<u16>(),
            pick in 0usize..4,
        ) {
            let value = blocked_v6_prefix(pick, host);
            let mut feed = feed();
            prop_assert!(
                publish_one(&mut feed, IndicatorKind::Cidr, &value).is_err(),
                "{value}"
            );
        }

        #[test]
        fn three_label_public_suffix_names_never_reach_a_feed(
            label in "[a-z][a-z0-9-]{0,10}[a-z0-9]",
            pick in 0usize..3,
        ) {
            prop_assume!(!label.contains("--") && !label.ends_with('-'));
            let suffix = ["co.uk", "github.io", "com.au"][pick];
            let value = format!("{label}.{suffix}");
            let mut feed = FeedVersions::open(empty_policy());
            prop_assert!(
                publish_one(&mut feed, IndicatorKind::Domain, &value).is_err(),
                "{value}"
            );
        }
    }

    fn blocked_v4_prefix(pick: usize, host: u8, len: u8) -> String {
        let (base, floor): (std::net::Ipv4Addr, u8) = match pick % 10 {
            0 => (std::net::Ipv4Addr::new(10, host, 1, 1), 8),
            1 => (std::net::Ipv4Addr::new(192, 168, host, 1), 16),
            2 => (std::net::Ipv4Addr::new(172, 16 + (host % 16), 1, 1), 12),
            3 => (std::net::Ipv4Addr::new(127, host, 0, 1), 8),
            4 => (std::net::Ipv4Addr::new(100, 64 + (host % 64), 0, 1), 10),
            5 => (std::net::Ipv4Addr::new(169, 254, host, 1), 16),
            6 => (std::net::Ipv4Addr::new(8, 8, 8, host), 24),
            7 => (std::net::Ipv4Addr::new(9, 9, 9, host), 24),
            8 => (std::net::Ipv4Addr::new(203, 0, 113, host), 24),
            _ => (std::net::Ipv4Addr::new(198, 51, 100, host), 24),
        };
        let len = u32::from(len.max(floor));
        let host_bits = 32 - len;
        let host_mask = if host_bits == 0 {
            0
        } else {
            (1u32 << host_bits) - 1
        };
        let network = u32::from(base) & !host_mask;
        format!("{}/{}", std::net::Ipv4Addr::from(network), len)
    }

    fn blocked_v6_prefix(pick: usize, host: u16) -> String {
        let low = u32::from(host) % 256;
        match pick % 4 {
            0 => format!("fd{low:02x}::/32"),
            1 => {
                let hi = 0x80 + (u32::from(host) % 0x40);
                format!("fe{hi:02x}::/32")
            }
            2 => format!("ff{low:02x}::/32"),
            _ => format!("2606:4700:4700:{host:x}::/64"),
        }
    }
}

#[test]
fn expiry_sweep_publishes_a_new_version_and_render_waits_for_it() {
    let mut feed = FeedVersions::open(empty_policy());
    let mut short = entry(IndicatorKind::Ip, "1.0.0.1");
    short.expires_at = Some(NOW + 10);
    feed.publish(
        &proposal(vec![short, entry(IndicatorKind::Ip, "1.1.1.1")]),
        NOW,
    )
    .expect("publish");
    assert!(
        feed.render(FeedFormat::PanosEdl, IndicatorKind::Ip, NOW + 11)
            .is_err()
    );
    let outcome = feed.sweep_expired(NOW + 11).expect("sweep");
    assert_eq!(outcome, SweepOutcome::Published { number: 2 });
    let text = feed
        .render(FeedFormat::PanosEdl, IndicatorKind::Ip, NOW + 11)
        .expect("render");
    assert_eq!(text, "1.1.1.1\n");
    assert_eq!(
        feed.sweep_expired(NOW + 11).expect("unchanged"),
        SweepOutcome::Unchanged { number: 2 }
    );
}

#[test]
fn render_fails_closed_when_policy_later_allowlists_an_entry() {
    let mut feed = FeedVersions::open(empty_policy());
    publish_one(&mut feed, IndicatorKind::Ip, "1.1.1.1").expect("publish");
    feed.update_policy(policy(&[], &["1.1.1.1/32"], &[], Limits::default()));
    assert!(
        feed.render(FeedFormat::FortigateThreatFeed, IndicatorKind::Ip, NOW)
            .is_err()
    );
}

#[test]
fn forged_reserved_indicator_cannot_be_rendered() {
    let forged = FeedIndicator::forge(IndicatorKind::Ip, "10.1.1.1", NOW + WEEK, false);
    let err = render_feed(
        FeedFormat::PanosEdl,
        IndicatorKind::Ip,
        &[forged],
        &empty_policy(),
        NOW,
    )
    .expect_err("reserved");
    assert!(matches!(err, crate::render::RenderError::Rejected { .. }));

    let public = FeedIndicator::forge(IndicatorKind::Ip, "1.1.1.1", NOW + WEEK, false);
    let text = render_feed(
        FeedFormat::OpnsenseUrlTable,
        IndicatorKind::Ip,
        &[public],
        &empty_policy(),
        NOW,
    )
    .expect("public");
    assert_eq!(text, "1.1.1.1\n");
}

#[test]
fn golden_documents_and_digest_are_stable() {
    let mut feed = FeedVersions::open(empty_policy());
    feed.publish(
        &proposal(vec![
            entry(IndicatorKind::Ip, "1.1.1.1"),
            entry(IndicatorKind::Ip, "2606:4700:4700::1111"),
            entry(IndicatorKind::Cidr, "9.9.9.0/24"),
            entry(IndicatorKind::Domain, "blocked.example"),
        ]),
        NOW,
    )
    .expect("publish");
    let snapshot = feed.latest().expect("snapshot");
    let expected = include_str!("../tests/fixtures/snapshot-content.txt");
    assert_eq!(canonical_content(snapshot.entries()), expected);
    let content_digest = sha256_hex(expected.as_bytes());
    assert_eq!(snapshot.manifest().content_digest(), content_digest);
    let preimage = format!("1\n-\n{content_digest}\n");
    assert_eq!(
        snapshot.manifest().digest(),
        sha256_hex(preimage.as_bytes())
    );

    for (format, kind, fixture) in [
        (
            FeedFormat::PanosEdl,
            IndicatorKind::Ip,
            include_str!("../tests/fixtures/panos_edl_ip.txt"),
        ),
        (
            FeedFormat::PanosEdl,
            IndicatorKind::Cidr,
            include_str!("../tests/fixtures/panos_edl_cidr.txt"),
        ),
        (
            FeedFormat::PanosEdl,
            IndicatorKind::Domain,
            include_str!("../tests/fixtures/panos_edl_domain.txt"),
        ),
        (
            FeedFormat::FortigateThreatFeed,
            IndicatorKind::Ip,
            include_str!("../tests/fixtures/fortigate_threat_ip.txt"),
        ),
        (
            FeedFormat::FortigateThreatFeed,
            IndicatorKind::Cidr,
            include_str!("../tests/fixtures/fortigate_threat_cidr.txt"),
        ),
        (
            FeedFormat::FortigateThreatFeed,
            IndicatorKind::Domain,
            include_str!("../tests/fixtures/fortigate_threat_domain.txt"),
        ),
        (
            FeedFormat::OpnsenseUrlTable,
            IndicatorKind::Ip,
            include_str!("../tests/fixtures/opnsense_url_table_ip.txt"),
        ),
        (
            FeedFormat::OpnsenseUrlTable,
            IndicatorKind::Cidr,
            include_str!("../tests/fixtures/opnsense_url_table_cidr.txt"),
        ),
        (
            FeedFormat::OpnsenseUrlTable,
            IndicatorKind::Domain,
            include_str!("../tests/fixtures/opnsense_url_table_domain.txt"),
        ),
        (
            FeedFormat::JunosDynamicAddress,
            IndicatorKind::Ip,
            include_str!("../tests/fixtures/junos_dynamic_address_ip.txt"),
        ),
        (
            FeedFormat::JunosDynamicAddress,
            IndicatorKind::Cidr,
            include_str!("../tests/fixtures/junos_dynamic_address_cidr.txt"),
        ),
    ] {
        assert_eq!(
            feed.render(format, kind, NOW).expect("render"),
            fixture,
            "{format:?} {kind:?}"
        );
    }
    let err = feed
        .render(FeedFormat::JunosDynamicAddress, IndicatorKind::Domain, NOW)
        .expect_err("junos domain");
    assert!(matches!(err, RenderError::UnsupportedKind { .. }));
}

#[test]
fn per_change_cap_does_not_limit_the_live_feed() {
    let mut feed = FeedVersions::open(policy(
        &[],
        &[],
        &[],
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
    ));
    publish_one(&mut feed, IndicatorKind::Ip, "1.1.1.1").expect("one");
    publish_one(&mut feed, IndicatorKind::Ip, "1.0.0.1").expect("another change");
    let err = feed
        .publish(
            &proposal(vec![
                entry(IndicatorKind::Domain, "one.example"),
                entry(IndicatorKind::Domain, "two.example"),
            ]),
            NOW,
        )
        .expect_err("cap");
    assert!(matches!(
        err,
        VersionError::Admit(AdmitError::TooMany { count: 2, max: 1 })
    ));
    assert_eq!(feed.latest().expect("snap").entries().len(), 2);
}
