//! Fail-closed admission. A change is accepted whole or not at all.

use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;

use crate::model::{Proposal, ProposedEntry, kind_tag};
use crate::range::{Indicator, IndicatorKind, ValidationError, validate_indicator};

const MAX_SOURCE_BYTES: usize = 128;
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
const MAX_TTL_LIMIT_SECS: i64 = 30 * SECONDS_PER_DAY;

/// Tunables for [`Policy`]. Invalid combinations are rejected by [`Policy::try_new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum entries in one change.
    pub max_entries: usize,
    /// Lifetime used when a proposal omits expiry, in seconds.
    pub default_ttl_secs: i64,
    /// Longest accepted lifetime, in seconds. Cannot exceed 30 days.
    pub max_ttl_secs: i64,
    /// Shortest IPv4 prefix accepted without an explicit exception. At least 24.
    pub min_ipv4_prefix: u8,
    /// Shortest IPv6 prefix accepted without an explicit exception. At least 48.
    pub min_ipv6_prefix: u8,
    /// When true, an entry may opt into a prefix shorter than the minimum.
    pub permit_explicit_broad: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100,
            default_ttl_secs: 7 * SECONDS_PER_DAY,
            max_ttl_secs: MAX_TTL_LIMIT_SECS,
            min_ipv4_prefix: 24,
            min_ipv6_prefix: 48,
            permit_explicit_broad: false,
        }
    }
}

/// Why a policy could not be built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// The per-change cap is zero.
    #[error("entry cap must be at least 1")]
    EntryCap,
    /// Default or maximum lifetime is out of range.
    #[error("ttl bounds are invalid")]
    Ttl,
    /// A prefix minimum is outside the supported range.
    #[error("prefix minimum is outside the allowed range")]
    PrefixMinimum,
    /// An allowlist suffix is not a canonical domain of at least two labels.
    #[error("allowlist domain suffix is invalid")]
    Suffix,
}

/// Operator policy applied before a version is published and again before render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    own_prefixes: Vec<IpNet>,
    allow_cidrs: Vec<IpNet>,
    allow_suffixes: Vec<String>,
    max_entries: usize,
    default_ttl_secs: i64,
    max_ttl_secs: i64,
    min_ipv4_prefix: u8,
    min_ipv6_prefix: u8,
    permit_explicit_broad: bool,
}

impl Policy {
    /// Build a policy. Prefix lists are matched as CIDR overlap.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when a limit or a domain suffix is not acceptable.
    pub fn try_new(
        own_prefixes: Vec<IpNet>,
        allow_cidrs: Vec<IpNet>,
        allow_domain_suffixes: impl IntoIterator<Item = impl AsRef<str>>,
        limits: Limits,
    ) -> Result<Self, PolicyError> {
        if limits.max_entries == 0 {
            return Err(PolicyError::EntryCap);
        }
        if limits.default_ttl_secs <= 0
            || limits.max_ttl_secs < limits.default_ttl_secs
            || limits.max_ttl_secs > MAX_TTL_LIMIT_SECS
        {
            return Err(PolicyError::Ttl);
        }
        if !(24..=32).contains(&limits.min_ipv4_prefix)
            || !(48..=128).contains(&limits.min_ipv6_prefix)
        {
            return Err(PolicyError::PrefixMinimum);
        }
        let mut allow_suffixes = Vec::new();
        for suffix in allow_domain_suffixes {
            allow_suffixes
                .push(normalize_domain(suffix.as_ref()).map_err(|_| PolicyError::Suffix)?);
        }
        Ok(Self {
            own_prefixes,
            allow_cidrs,
            allow_suffixes,
            max_entries: limits.max_entries,
            default_ttl_secs: limits.default_ttl_secs,
            max_ttl_secs: limits.max_ttl_secs,
            min_ipv4_prefix: limits.min_ipv4_prefix,
            min_ipv6_prefix: limits.min_ipv6_prefix,
            permit_explicit_broad: limits.permit_explicit_broad,
        })
    }

    /// Per-change entry cap.
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Whether an entry may opt into a shorter prefix.
    #[must_use]
    pub fn permit_explicit_broad(&self) -> bool {
        self.permit_explicit_broad
    }
}

/// An indicator that passed admission. Fields stay private so callers cannot
/// widen a value after the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedIndicator {
    kind: IndicatorKind,
    value: String,
    source: String,
    confidence: u8,
    first_seen: i64,
    last_seen: i64,
    expires_at: i64,
    broad_explicit: bool,
}

impl FeedIndicator {
    /// Indicator kind.
    #[must_use]
    pub fn kind(&self) -> IndicatorKind {
        self.kind
    }

    /// Canonical indicator text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Origin label.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Confidence from 0 to 100.
    #[must_use]
    pub fn confidence(&self) -> u8 {
        self.confidence
    }

    /// First-seen time, as Unix seconds.
    #[must_use]
    pub fn first_seen(&self) -> i64 {
        self.first_seen
    }

    /// Last-seen time, as Unix seconds.
    #[must_use]
    pub fn last_seen(&self) -> i64 {
        self.last_seen
    }

    /// Expiry, as Unix seconds.
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Whether admission recorded an explicit broad-prefix exception.
    #[must_use]
    pub fn broad_explicit(&self) -> bool {
        self.broad_explicit
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_row(
        kind: IndicatorKind,
        value: String,
        source: String,
        confidence: u8,
        first_seen: i64,
        last_seen: i64,
        expires_at: i64,
        broad_explicit: bool,
    ) -> Self {
        Self {
            kind,
            value,
            source,
            confidence,
            first_seen,
            last_seen,
            expires_at,
            broad_explicit,
        }
    }

    /// Stable kind tag used in the snapshot digest.
    #[must_use]
    pub fn kind_tag(&self) -> &'static str {
        kind_tag(self.kind)
    }

    #[cfg(test)]
    pub(crate) fn forge(
        kind: IndicatorKind,
        value: &str,
        expires_at: i64,
        broad_explicit: bool,
    ) -> Self {
        Self {
            kind,
            value: value.to_string(),
            source: "lab".to_string(),
            confidence: 50,
            first_seen: 0,
            last_seen: 0,
            expires_at,
            broad_explicit,
        }
    }
}

/// Why one proposed entry was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EntryError {
    /// The indicator failed the hard range check.
    #[error(transparent)]
    Indicator(#[from] ValidationError),
    /// The text is not the canonical form of its kind.
    #[error("indicator is not canonical")]
    Uncanonical,
    /// The prefix is shorter than the policy minimum.
    #[error("prefix /{prefix_len} is shorter than /{minimum}")]
    BroadPrefix {
        /// Observed prefix length.
        prefix_len: u8,
        /// Policy minimum.
        minimum: u8,
    },
    /// The indicator overlaps an operator-owned prefix.
    #[error("indicator overlaps an operator prefix")]
    OwnPrefix,
    /// The indicator matches the allowlist.
    #[error("indicator is allowlisted")]
    Allowlisted,
    /// The expiry is missing, already past, or not after last-seen.
    #[error("expiry is not acceptable")]
    Expiry,
    /// The lifetime is longer than the policy maximum.
    #[error("lifetime of {ttl_secs}s exceeds {max_secs}s")]
    Ttl {
        /// Proposed lifetime in seconds.
        ttl_secs: i64,
        /// Policy maximum in seconds.
        max_secs: i64,
    },
    /// Seen-times are in the future, out of order, or overflow.
    #[error("seen-times are not acceptable")]
    Timestamp,
    /// The same indicator is already live, or repeated in this change.
    #[error("indicator is already in the feed")]
    Duplicate,
    /// Confidence is above 100.
    #[error("confidence is out of range")]
    Confidence,
    /// The source is empty, too long, or not a single token.
    #[error("source is not a single token")]
    Source,
    /// The last two labels are a known multi-label public suffix.
    #[error("domain needs another label under a public suffix")]
    BroadDomain,
}

/// Why a change was rejected. Nothing from that change is published.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdmitError {
    /// `now` is negative.
    #[error("clock is not acceptable")]
    Clock,
    /// The change has no entries.
    #[error("change is empty")]
    Empty,
    /// The change exceeds the entry cap.
    #[error("change has {count} entries; limit is {max}")]
    TooMany {
        /// Entries in the change.
        count: usize,
        /// Policy cap.
        max: usize,
    },
    /// One entry failed. `index` is the position in the proposal.
    #[error("entry {index}: {reason}")]
    Entry {
        /// Zero-based index in the proposal.
        index: usize,
        /// Why that entry failed.
        reason: EntryError,
    },
    /// A row carried forward from the live list no longer passes screening.
    #[error("live entry {index}: {reason}")]
    Live {
        /// Zero-based index in the live list after expired rows are dropped.
        index: usize,
        /// Why that row failed.
        reason: EntryError,
    },
}

/// Admit `proposal` against `live`. On success, returns the next full entry list.
///
/// # Errors
///
/// Returns [`AdmitError`] and does not modify `live`. An expired live row with
/// the same indicator is replaced. An unexpired match is a duplicate.
pub fn admit(
    policy: &Policy,
    live: &[FeedIndicator],
    proposal: &Proposal,
    now: i64,
) -> Result<Vec<FeedIndicator>, AdmitError> {
    if now < 0 {
        return Err(AdmitError::Clock);
    }
    if proposal.entries.is_empty() {
        return Err(AdmitError::Empty);
    }
    if proposal.entries.len() > policy.max_entries {
        return Err(AdmitError::TooMany {
            count: proposal.entries.len(),
            max: policy.max_entries,
        });
    }
    let mut next = live.to_vec();
    for (index, entry) in proposal.entries.iter().enumerate() {
        let admitted =
            admit_one(policy, entry, now).map_err(|reason| AdmitError::Entry { index, reason })?;
        upsert(&mut next, admitted, now).map_err(|reason| AdmitError::Entry { index, reason })?;
    }
    next.retain(|entry| entry.expires_at > now);
    screen_all(&next, policy, now).map_err(|(index, reason)| AdmitError::Live { index, reason })?;
    sort_entries(&mut next);
    Ok(next)
}

/// Screen every row. On failure returns the index of the first failing row.
pub(crate) fn screen_all(
    entries: &[FeedIndicator],
    policy: &Policy,
    now: i64,
) -> Result<(), (usize, EntryError)> {
    entries
        .iter()
        .enumerate()
        .try_for_each(|(index, entry)| screen(entry, policy, now).map_err(|reason| (index, reason)))
}

/// Re-check one stored entry before it is rendered.
pub(crate) fn screen(entry: &FeedIndicator, policy: &Policy, now: i64) -> Result<(), EntryError> {
    if now < 0 {
        return Err(EntryError::Timestamp);
    }
    if entry.expires_at <= now {
        return Err(EntryError::Expiry);
    }
    screen_stored(entry, policy)
}

/// Re-check a stored row without applying the expiry clock.
///
/// History must still load after a row's lifetime has passed. Expiry is
/// enforced when the row is rendered or carried into a new version.
pub(crate) fn screen_stored(entry: &FeedIndicator, policy: &Policy) -> Result<(), EntryError> {
    let indicator = Indicator {
        kind: entry.kind,
        value: entry.value.clone(),
    };
    validate_indicator(&indicator)?;
    match entry.kind {
        IndicatorKind::Ip => {
            let ip = parse_ip(&entry.value)?;
            if entry.value != ip.to_string() {
                return Err(EntryError::Uncanonical);
            }
            reject_ip(ip, policy)?;
        }
        IndicatorKind::Cidr => {
            let net = parse_cidr(&entry.value)?;
            if entry.value != net.to_string() {
                return Err(EntryError::Uncanonical);
            }
            reject_cidr(net, entry.broad_explicit, policy)?;
        }
        IndicatorKind::Domain => {
            let canonical = normalize_domain(&entry.value)?;
            if canonical != entry.value {
                return Err(EntryError::Uncanonical);
            }
            reject_broad_domain(&canonical)?;
            if domain_matches(&entry.value, &policy.allow_suffixes) {
                return Err(EntryError::Allowlisted);
            }
        }
    }
    Ok(())
}

fn admit_one(
    policy: &Policy,
    entry: &ProposedEntry,
    now: i64,
) -> Result<FeedIndicator, EntryError> {
    let meta = metadata(entry, policy, now)?;
    let (value, broad_explicit) = match entry.kind {
        IndicatorKind::Ip => {
            let ip = parse_ip(entry.value.trim())?;
            let canonical = ip.to_string();
            if entry.value.trim() != canonical {
                return Err(EntryError::Uncanonical);
            }
            validate_indicator(&Indicator {
                kind: IndicatorKind::Ip,
                value: canonical.clone(),
            })?;
            reject_ip(ip, policy)?;
            (canonical, false)
        }
        IndicatorKind::Cidr => {
            let net = parse_cidr(entry.value.trim())?;
            let canonical = net.to_string();
            if entry.value.trim() != canonical {
                return Err(EntryError::Uncanonical);
            }
            validate_indicator(&Indicator {
                kind: IndicatorKind::Cidr,
                value: canonical.clone(),
            })?;
            reject_cidr(net, entry.allow_broad_prefix, policy)?;
            let shorter_than_minimum = net.prefix_len() < minimum_prefix(net, policy);
            (
                canonical,
                entry.allow_broad_prefix && policy.permit_explicit_broad && shorter_than_minimum,
            )
        }
        IndicatorKind::Domain => {
            let canonical = normalize_domain(entry.value.trim())?;
            reject_broad_domain(&canonical)?;
            if domain_matches(&canonical, &policy.allow_suffixes) {
                return Err(EntryError::Allowlisted);
            }
            (canonical, false)
        }
    };
    Ok(FeedIndicator {
        kind: entry.kind,
        value,
        source: meta.source,
        confidence: meta.confidence,
        first_seen: meta.first_seen,
        last_seen: meta.last_seen,
        expires_at: meta.expires_at,
        broad_explicit,
    })
}

struct Meta {
    source: String,
    confidence: u8,
    first_seen: i64,
    last_seen: i64,
    expires_at: i64,
}

fn metadata(entry: &ProposedEntry, policy: &Policy, now: i64) -> Result<Meta, EntryError> {
    if entry.confidence > 100 {
        return Err(EntryError::Confidence);
    }
    let source = entry.source.trim();
    if source.is_empty()
        || source.len() > MAX_SOURCE_BYTES
        || source.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(EntryError::Source);
    }
    if entry.first_seen > now || entry.last_seen > now || entry.first_seen > entry.last_seen {
        return Err(EntryError::Timestamp);
    }
    let expires_at = match entry.expires_at {
        Some(value) => value,
        None => now
            .checked_add(policy.default_ttl_secs)
            .ok_or(EntryError::Timestamp)?,
    };
    if expires_at <= now || expires_at < entry.last_seen {
        return Err(EntryError::Expiry);
    }
    let ttl_secs = expires_at.checked_sub(now).ok_or(EntryError::Timestamp)?;
    if ttl_secs > policy.max_ttl_secs {
        return Err(EntryError::Ttl {
            ttl_secs,
            max_secs: policy.max_ttl_secs,
        });
    }
    Ok(Meta {
        source: source.to_string(),
        confidence: entry.confidence,
        first_seen: entry.first_seen,
        last_seen: entry.last_seen,
        expires_at,
    })
}

fn upsert(rows: &mut Vec<FeedIndicator>, row: FeedIndicator, now: i64) -> Result<(), EntryError> {
    if let Some(pos) = rows
        .iter()
        .position(|existing| existing.kind == row.kind && existing.value == row.value)
    {
        if rows[pos].expires_at > now {
            return Err(EntryError::Duplicate);
        }
        rows[pos] = row;
        return Ok(());
    }
    rows.push(row);
    Ok(())
}

fn sort_entries(rows: &mut [FeedIndicator]) {
    rows.sort_by(|left, right| {
        kind_tag(left.kind)
            .cmp(kind_tag(right.kind))
            .then_with(|| left.value.cmp(&right.value))
    });
}

fn parse_ip(value: &str) -> Result<IpAddr, EntryError> {
    value.parse().map_err(|_| {
        EntryError::Indicator(ValidationError::Unparseable {
            kind: IndicatorKind::Ip,
            value: value.to_string(),
        })
    })
}

fn parse_cidr(value: &str) -> Result<IpNet, EntryError> {
    value.parse().map_err(|_| {
        EntryError::Indicator(ValidationError::Unparseable {
            kind: IndicatorKind::Cidr,
            value: value.to_string(),
        })
    })
}

fn reject_ip(ip: IpAddr, policy: &Policy) -> Result<(), EntryError> {
    if policy.own_prefixes.iter().any(|net| net.contains(&ip)) {
        return Err(EntryError::OwnPrefix);
    }
    if policy.allow_cidrs.iter().any(|net| net.contains(&ip)) {
        return Err(EntryError::Allowlisted);
    }
    Ok(())
}

fn minimum_prefix(net: IpNet, policy: &Policy) -> u8 {
    match net {
        IpNet::V4(_) => policy.min_ipv4_prefix,
        IpNet::V6(_) => policy.min_ipv6_prefix,
    }
}

fn reject_cidr(net: IpNet, explicit: bool, policy: &Policy) -> Result<(), EntryError> {
    let minimum = minimum_prefix(net, policy);
    if net.prefix_len() < minimum && !(explicit && policy.permit_explicit_broad) {
        return Err(EntryError::BroadPrefix {
            prefix_len: net.prefix_len(),
            minimum,
        });
    }
    if policy.own_prefixes.iter().any(|own| overlaps(net, *own)) {
        return Err(EntryError::OwnPrefix);
    }
    if policy.allow_cidrs.iter().any(|allow| overlaps(net, *allow)) {
        return Err(EntryError::Allowlisted);
    }
    Ok(())
}

fn overlaps(left: IpNet, right: IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => cidr_overlap(
            left.prefix_len(),
            right.prefix_len(),
            left.contains(&right.addr()),
            right.contains(&left.addr()),
        ),
        (IpNet::V6(left), IpNet::V6(right)) => cidr_overlap(
            left.prefix_len(),
            right.prefix_len(),
            left.contains(&right.addr()),
            right.contains(&left.addr()),
        ),
        _ => false,
    }
}

fn cidr_overlap(
    left_len: u8,
    right_len: u8,
    left_contains_right: bool,
    right_contains_left: bool,
) -> bool {
    if left_len <= right_len {
        left_contains_right
    } else {
        right_contains_left
    }
}

fn domain_matches(domain: &str, suffixes: &[String]) -> bool {
    suffixes.iter().any(|suffix| is_suffix(domain, suffix))
}

fn is_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    match domain.strip_suffix(suffix) {
        Some(rest) => rest.ends_with('.'),
        None => false,
    }
}

/// Canonical DNS name: lowercase, no trailing dot, LDH labels, alphabetic TLD.
///
/// # Errors
///
/// Returns [`EntryError`] when the value is not a two-or-more-label DNS name.
pub fn normalize_domain(raw: &str) -> Result<String, EntryError> {
    let value = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || value.parse::<IpAddr>().is_ok() {
        return Err(unparseable_domain(raw));
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| !valid_label(label)) {
        return Err(unparseable_domain(&value));
    }
    // A TLD is alphabetic (or `xn--`). A numeric last label is an address in
    // a legacy dotted form, which must not be admitted as a name.
    let numeric_tld = labels
        .last()
        .is_none_or(|tld| !tld.starts_with(|c: char| c.is_ascii_alphabetic()));
    if numeric_tld {
        return Err(unparseable_domain(&value));
    }
    validate_indicator(&Indicator {
        kind: IndicatorKind::Domain,
        value: value.clone(),
    })?;
    Ok(value)
}

/// Names shorter than a two-label public suffix plus two labels are too broad.
fn reject_broad_domain(canonical: &str) -> Result<(), EntryError> {
    let labels: Vec<&str> = canonical.split('.').collect();
    if labels.len() < 4 && last_two_are_public_suffix(&labels) {
        return Err(EntryError::BroadDomain);
    }
    Ok(())
}

fn last_two_are_public_suffix(labels: &[&str]) -> bool {
    let Some((tld, rest)) = labels.split_last() else {
        return false;
    };
    let Some(sld) = rest.last() else {
        return false;
    };
    let mut last_two = String::with_capacity(sld.len() + 1 + tld.len());
    last_two.push_str(sld);
    last_two.push('.');
    last_two.push_str(tld);
    crate::two_label_public_suffixes::TWO_LABEL_PUBLIC_SUFFIXES
        .binary_search(&last_two.as_str())
        .is_ok()
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn unparseable_domain(value: &str) -> EntryError {
    EntryError::Indicator(ValidationError::Unparseable {
        kind: IndicatorKind::Domain,
        value: value.trim().to_string(),
    })
}
