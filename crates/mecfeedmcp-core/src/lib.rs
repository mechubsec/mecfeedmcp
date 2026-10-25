//! Indicator admission, snapshot versions and signatures, and vendor feed renderers.
//!
//! Pure logic: no I/O. Source readers, change-set lifecycle, and the feed
//! HTTP server live in the other workspace crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod model;
mod policy;
mod range;
mod render;
mod signature;
mod two_label_public_suffixes;
mod version;

pub use model::{Proposal, ProposedEntry};
pub use policy::{
    AdmitError, EntryError, FeedIndicator, Limits, Policy, PolicyError, normalize_domain,
};
pub use range::{
    Indicator, IndicatorKind, MIN_IPV4_PREFIX_LEN, MIN_IPV6_PREFIX_LEN, ValidationError,
    validate_indicator,
};
pub use render::{FeedFormat, RenderError, render_feed};
pub use signature::{
    PublicKey, SIGNATURE_FILE_MAX_BYTES, SIGNATURE_FILE_NAME, SignatureError, SignatureFile,
    TrustedKeys, encode_signature_file, parse_signature_file, signed_message, signing_input,
};
pub use version::{
    FeedVersions, Manifest, PlannedSnapshot, Snapshot, SnapshotDocument, SnapshotRow, SweepOutcome,
    VersionError,
};

/// Crate version from the workspace package.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests;
