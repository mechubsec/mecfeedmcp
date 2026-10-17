//! Untrusted change proposals. Admission turns these into feed entries.

use crate::range::IndicatorKind;

/// One proposed feed entry, before admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedEntry {
    /// Declared indicator kind.
    pub kind: IndicatorKind,
    /// Raw indicator text. Admission stores the canonical form.
    pub value: String,
    /// Origin label. A single token, at most 128 bytes.
    pub source: String,
    /// Confidence from 0 to 100 inclusive.
    pub confidence: u8,
    /// Unix seconds. Must not be later than `now` or `last_seen`.
    pub first_seen: i64,
    /// Unix seconds. Must not be later than `now`.
    pub last_seen: i64,
    /// Unix seconds. `None` uses the policy default lifetime.
    pub expires_at: Option<i64>,
    /// Ask to keep a prefix shorter than the policy minimum.
    ///
    /// Admission honors this only when the policy also permits it, and never
    /// below the hard prefix floor.
    pub allow_broad_prefix: bool,
}

/// A set of proposed entries. The cap applies to this set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Entries in proposal order.
    pub entries: Vec<ProposedEntry>,
}

pub(crate) fn kind_tag(kind: IndicatorKind) -> &'static str {
    match kind {
        IndicatorKind::Cidr => "cidr",
        IndicatorKind::Domain => "domain",
        IndicatorKind::Ip => "ip",
    }
}
