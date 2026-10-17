//! Vendor feed documents rendered from an already-admitted snapshot.
//!
//! PAN-OS, FortiGate, and OPNsense each receive one canonical indicator per
//! line. Junos dynamic-address receives addresses and prefixes only.

use thiserror::Error;

use crate::policy::{EntryError, FeedIndicator, Policy, screen};
use crate::range::IndicatorKind;

/// Feed document a firewall pulls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    /// PAN-OS external dynamic list. Addresses, prefixes, and domains.
    PanosEdl,
    /// Junos SRX dynamic-address feed. Addresses and prefixes only.
    JunosDynamicAddress,
    /// FortiGate external threat feed. Addresses, prefixes, and domains.
    FortigateThreatFeed,
    /// OPNsense URL-table alias. Addresses, prefixes, and domains.
    OpnsenseUrlTable,
}

/// Why a snapshot could not be rendered.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RenderError {
    /// No snapshot has been published.
    #[error("no published version")]
    Empty,
    /// An entry failed screening. No document is returned.
    #[error("feed entry {index} cannot be rendered: {reason}")]
    Rejected {
        /// Position in the snapshot.
        index: usize,
        /// Why the entry was rejected.
        reason: EntryError,
    },
}

/// Render `entries` for `format`.
///
/// Every entry is screened again. One rejected entry fails the whole document.
///
/// # Errors
///
/// Returns [`RenderError::Rejected`] when screening fails.
pub fn render_feed(
    format: FeedFormat,
    entries: &[FeedIndicator],
    policy: &Policy,
    now: i64,
) -> Result<String, RenderError> {
    for (index, entry) in entries.iter().enumerate() {
        screen(entry, policy, now).map_err(|reason| RenderError::Rejected { index, reason })?;
    }
    let mut lines = Vec::new();
    for entry in entries {
        if format == FeedFormat::JunosDynamicAddress && entry.kind() == IndicatorKind::Domain {
            continue;
        }
        lines.push(entry.value().to_string());
    }
    lines.sort_unstable();
    if lines.is_empty() {
        return Ok(String::new());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Ok(out)
}
