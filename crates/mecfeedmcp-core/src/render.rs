//! Vendor feed documents rendered from an already-admitted snapshot.
//!
//! Each document is one format and one indicator kind. PAN-OS, FortiGate, and
//! OPNsense render address, prefix, and domain documents. Junos dynamic-address
//! renders address and prefix documents only.

use thiserror::Error;

use crate::policy::{EntryError, FeedIndicator, Policy, screen};
use crate::range::IndicatorKind;

/// Feed document a firewall pulls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    /// PAN-OS external dynamic list. One document per indicator kind.
    PanosEdl,
    /// Junos SRX dynamic-address feed. Address and prefix documents only.
    JunosDynamicAddress,
    /// FortiGate external threat feed. One document per indicator kind.
    FortigateThreatFeed,
    /// OPNsense URL-table alias. One document per indicator kind.
    OpnsenseUrlTable,
}

impl FeedFormat {
    /// Whether this format publishes a document for `kind`.
    #[must_use]
    pub fn supports(self, kind: IndicatorKind) -> bool {
        match self {
            Self::JunosDynamicAddress => kind != IndicatorKind::Domain,
            Self::PanosEdl | Self::FortigateThreatFeed | Self::OpnsenseUrlTable => true,
        }
    }
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
    /// This format has no document for that indicator kind.
    #[error("{format:?} does not render {kind:?} indicators")]
    UnsupportedKind {
        /// Requested format.
        format: FeedFormat,
        /// Requested kind.
        kind: IndicatorKind,
    },
}

/// Render `kind` entries from `entries` for `format`.
///
/// Every entry is screened again. One rejected entry fails the whole document.
/// Lines of other kinds are omitted.
///
/// # Errors
///
/// Returns [`RenderError::UnsupportedKind`] when the format has no document
/// for `kind`, and [`RenderError::Rejected`] when screening fails.
pub fn render_feed(
    format: FeedFormat,
    kind: IndicatorKind,
    entries: &[FeedIndicator],
    policy: &Policy,
    now: i64,
) -> Result<String, RenderError> {
    if !format.supports(kind) {
        return Err(RenderError::UnsupportedKind { format, kind });
    }
    for (index, entry) in entries.iter().enumerate() {
        screen(entry, policy, now).map_err(|reason| RenderError::Rejected { index, reason })?;
    }
    let mut lines: Vec<String> = entries
        .iter()
        .filter(|entry| entry.kind() == kind)
        .map(|entry| entry.value().to_string())
        .collect();
    lines.sort_unstable();
    if lines.is_empty() {
        return Ok(String::new());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Ok(out)
}
