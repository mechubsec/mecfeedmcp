//! Immutable numbered snapshots. Rollback republishes a named earlier version.
//! An expiry sweep publishes a new version with the expired rows removed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::Proposal;
use crate::policy::{FeedIndicator, Policy, admit, screen_all, screen_stored};
use crate::range::IndicatorKind;
use crate::render::{FeedFormat, RenderError, render_feed};

/// Why a version operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// No snapshot has been published.
    #[error("no published version")]
    Empty,
    /// The target is unknown or is already the latest version.
    #[error("no such earlier version to republish")]
    NothingToRollBack,
    /// The latest version is not the one the caller expected. Nothing was published.
    #[error("latest version is {latest}, expected {expected}")]
    Stale {
        /// Version the caller expected to be latest.
        expected: u64,
        /// Actual latest version.
        latest: u64,
    },
    /// A restored row no longer passes the current policy. Nothing was published.
    #[error("restored entry {index}: {reason}")]
    Restored {
        /// Zero-based index in the target snapshot.
        index: usize,
        /// Why that row failed.
        reason: crate::policy::EntryError,
    },
    /// `now` is negative.
    #[error("clock is not acceptable")]
    Clock,
    /// Admission rejected the change. The log is unchanged.
    #[error(transparent)]
    Admit(#[from] crate::policy::AdmitError),
    /// The snapshot does not continue the current log. Nothing was published.
    #[error("snapshot does not follow the current feed")]
    Chain,
    /// The snapshot bytes do not match its digest. Nothing was published.
    #[error("snapshot digest does not match")]
    Digest,
    /// A stored row is not acceptable. Nothing was published.
    #[error("snapshot row is not acceptable")]
    Row,
}

/// Result of an expiry sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepOutcome {
    /// Every current entry was still unexpired.
    Unchanged {
        /// Current version number.
        number: u64,
    },
    /// A new version was appended without the expired entries.
    Published {
        /// New version number.
        number: u64,
    },
}

/// Digest and identity of one immutable snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    number: u64,
    parent: Option<u64>,
    content_digest: String,
    digest: String,
}

impl Manifest {
    /// Version number. The first published snapshot is 1.
    #[must_use]
    pub fn number(&self) -> u64 {
        self.number
    }

    /// Previous version, if this snapshot is not the first.
    #[must_use]
    pub fn parent(&self) -> Option<u64> {
        self.parent
    }

    /// Digest of the canonical entry bytes. Independent of the version number.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Digest binding the number, parent, and content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// One row of a snapshot document. Admission is what creates these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRow {
    /// Indicator kind.
    pub kind: IndicatorKind,
    /// Canonical indicator text.
    pub value: String,
    /// Origin label.
    pub source: String,
    /// Confidence from 0 to 100.
    pub confidence: u8,
    /// First-seen time, as Unix seconds.
    pub first_seen: i64,
    /// Last-seen time, as Unix seconds.
    pub last_seen: i64,
    /// Expiry, as Unix seconds.
    pub expires_at: i64,
    /// Whether admission recorded an explicit broad-prefix exception.
    pub broad_explicit: bool,
}

/// A snapshot document. The digests are checked before it joins a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDocument {
    /// Version number.
    pub number: u64,
    /// Previous version, absent for the first snapshot.
    pub parent: Option<u64>,
    /// Digest of the canonical entry bytes.
    pub content_digest: String,
    /// Digest binding the number, parent, and content digest.
    pub digest: String,
    /// Rows in stored order.
    pub entries: Vec<SnapshotRow>,
}

/// The snapshot `publish` would append, before it is appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedSnapshot {
    manifest: Manifest,
    entries: Vec<FeedIndicator>,
}

impl PlannedSnapshot {
    /// Version number this plan would publish.
    #[must_use]
    pub fn number(&self) -> u64 {
        self.manifest.number
    }

    /// Parent version, if the log is not empty.
    #[must_use]
    pub fn parent(&self) -> Option<u64> {
        self.manifest.parent
    }

    /// Digest of the canonical entry bytes.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.manifest.content_digest
    }

    /// Digest binding the number, parent, and content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.manifest.digest
    }

    /// Entries this plan would publish.
    #[must_use]
    pub fn entries(&self) -> &[FeedIndicator] {
        &self.entries
    }

    /// Document form of this plan.
    #[must_use]
    pub fn document(&self) -> SnapshotDocument {
        document_from(&self.manifest, &self.entries)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_digest(mut self) -> Self {
        self.manifest.digest = "ab".repeat(32);
        self
    }
}

/// One published snapshot. Entries cannot be edited in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    manifest: Manifest,
    entries: Vec<FeedIndicator>,
}

impl Snapshot {
    /// Identity and digests for this snapshot.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Entries in digest order.
    #[must_use]
    pub fn entries(&self) -> &[FeedIndicator] {
        &self.entries
    }
}

/// Append-only feed history under one policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedVersions {
    policy: Policy,
    snapshots: Vec<Snapshot>,
}

impl FeedVersions {
    /// Start an empty history.
    #[must_use]
    pub fn open(policy: Policy) -> Self {
        Self {
            policy,
            snapshots: Vec::new(),
        }
    }

    /// Policy used for later admission and rendering.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Replace the policy. Existing snapshots are not rewritten.
    pub fn update_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// Latest snapshot.
    #[must_use]
    pub fn latest(&self) -> Option<&Snapshot> {
        self.snapshots.last()
    }

    /// Fingerprint of the published log. Empty logs have a fixed value.
    ///
    /// The format is `sha256:` and 64 lowercase hex digits.
    #[must_use]
    pub fn state_fingerprint(&self) -> String {
        let raw = match self.latest() {
            Some(snapshot) => snapshot.manifest.digest.as_str(),
            None => "mecfeed/empty",
        };
        format!("sha256:{}", sha256_hex(raw.as_bytes()))
    }

    /// Snapshot by version number.
    #[must_use]
    pub fn get(&self, number: u64) -> Option<&Snapshot> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.manifest.number == number)
    }

    /// Admit `proposal` and append the resulting snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Admit`] when admission fails. The log is unchanged.
    pub fn publish(&mut self, proposal: &Proposal, now: i64) -> Result<&Snapshot, VersionError> {
        let next = {
            let live = self
                .snapshots
                .last()
                .map(|snapshot| snapshot.entries.as_slice())
                .unwrap_or(&[]);
            admit(&self.policy, live, proposal, now)?
        };
        Ok(self.push(next))
    }

    /// Append a new snapshot with the entries of version `target`.
    ///
    /// The caller names the latest version it saw, so a retried call fails
    /// as stale instead of acting on a newer log. Restored rows are screened
    /// against the current policy.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Empty`], [`VersionError::Clock`],
    /// [`VersionError::Stale`], [`VersionError::NothingToRollBack`] (unknown
    /// target, or target is the latest) or [`VersionError::Restored`]. The log
    /// is unchanged on error.
    pub fn rollback_to(
        &mut self,
        target: u64,
        expected_latest: u64,
        now: i64,
    ) -> Result<&Snapshot, VersionError> {
        if now < 0 {
            return Err(VersionError::Clock);
        }
        let entries = {
            let latest = self.snapshots.last().ok_or(VersionError::Empty)?;
            let latest_number = latest.manifest.number;
            if latest_number != expected_latest {
                return Err(VersionError::Stale {
                    expected: expected_latest,
                    latest: latest_number,
                });
            }
            if target == latest_number {
                return Err(VersionError::NothingToRollBack);
            }
            let previous = self.get(target).ok_or(VersionError::NothingToRollBack)?;
            screen_all(&previous.entries, &self.policy, now)
                .map_err(|(index, reason)| VersionError::Restored { index, reason })?;
            previous.entries.clone()
        };
        Ok(self.push(entries))
    }

    /// Publish a new version when at least one entry is expired.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Empty`] when nothing has been published, and
    /// [`VersionError::Clock`] when `now` is negative.
    pub fn sweep_expired(&mut self, now: i64) -> Result<SweepOutcome, VersionError> {
        if now < 0 {
            return Err(VersionError::Clock);
        }
        let (number, kept, original_len) = {
            let latest = self.snapshots.last().ok_or(VersionError::Empty)?;
            let kept = latest
                .entries
                .iter()
                .filter(|entry| entry.expires_at() > now)
                .cloned()
                .collect::<Vec<_>>();
            (latest.manifest.number, kept, latest.entries.len())
        };
        if kept.len() == original_len {
            return Ok(SweepOutcome::Unchanged { number });
        }
        let number = self.push(kept).manifest.number;
        Ok(SweepOutcome::Published { number })
    }

    /// Render one format-and-kind document from the latest snapshot.
    ///
    /// Fails closed if any live entry is no longer acceptable.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when there is no snapshot, the format has no
    /// document for `kind`, or an entry fails screening.
    pub fn render(
        &self,
        format: FeedFormat,
        kind: IndicatorKind,
        now: i64,
    ) -> Result<String, RenderError> {
        let Some(latest) = self.latest() else {
            return Err(RenderError::Empty);
        };
        render_feed(format, kind, latest.entries(), &self.policy, now)
    }

    /// Admit `proposal` and describe the snapshot `publish` would append.
    ///
    /// The log is not modified.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Admit`] when admission fails.
    pub fn plan(&self, proposal: &Proposal, now: i64) -> Result<PlannedSnapshot, VersionError> {
        let live = self
            .snapshots
            .last()
            .map(|snapshot| snapshot.entries.as_slice())
            .unwrap_or(&[]);
        let entries = admit(&self.policy, live, proposal, now)?;
        Ok(self.preview(entries))
    }

    /// Describe the snapshot `rollback_to` would append. The log is not modified.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::rollback_to`]. The log is unchanged.
    pub fn plan_rollback(
        &self,
        target: u64,
        expected_latest: u64,
        now: i64,
    ) -> Result<PlannedSnapshot, VersionError> {
        if now < 0 {
            return Err(VersionError::Clock);
        }
        let latest = self.snapshots.last().ok_or(VersionError::Empty)?;
        let latest_number = latest.manifest.number;
        if latest_number != expected_latest {
            return Err(VersionError::Stale {
                expected: expected_latest,
                latest: latest_number,
            });
        }
        if target == latest_number {
            return Err(VersionError::NothingToRollBack);
        }
        let previous = self.get(target).ok_or(VersionError::NothingToRollBack)?;
        screen_all(&previous.entries, &self.policy, now)
            .map_err(|(index, reason)| VersionError::Restored { index, reason })?;
        Ok(self.preview(previous.entries.clone()))
    }

    /// Append `planned` when it is still the next snapshot for this log.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Chain`], [`VersionError::Digest`],
    /// [`VersionError::Row`], or [`VersionError::Clock`]. The log is unchanged
    /// on error.
    pub fn commit_planned(
        &mut self,
        planned: &PlannedSnapshot,
        now: i64,
    ) -> Result<&Snapshot, VersionError> {
        if now < 0 {
            return Err(VersionError::Clock);
        }
        screen_all(&planned.entries, &self.policy, now).map_err(|_| VersionError::Row)?;
        self.ensure_planned(planned)?;
        Ok(self.push(planned.entries.clone()))
    }

    /// Document for version `number`.
    #[must_use]
    pub fn document(&self, number: u64) -> Option<SnapshotDocument> {
        self.get(number)
            .map(|snapshot| document_from(&snapshot.manifest, &snapshot.entries))
    }

    /// Append a document whose digest and rows check out.
    ///
    /// Expired rows may load. A row that is not acceptable does not.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Chain`], [`VersionError::Digest`], or
    /// [`VersionError::Row`]. The log is unchanged on error.
    pub fn import_document(
        &mut self,
        document: SnapshotDocument,
        now: i64,
    ) -> Result<(), VersionError> {
        if now < 0 {
            return Err(VersionError::Clock);
        }
        let entries = rows_to_entries(&document.entries);
        let planned = PlannedSnapshot {
            manifest: Manifest {
                number: document.number,
                parent: document.parent,
                content_digest: document.content_digest,
                digest: document.digest,
            },
            entries,
        };
        self.ensure_planned(&planned)?;
        self.push(planned.entries);
        Ok(())
    }

    /// Drop the latest snapshot when its digest is `digest`.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Empty`] or [`VersionError::Digest`]. The log is
    /// unchanged on error.
    pub fn discard_latest_if_digest(&mut self, digest: &str) -> Result<(), VersionError> {
        let latest = self.snapshots.last().ok_or(VersionError::Empty)?;
        if latest.manifest.digest != digest {
            return Err(VersionError::Digest);
        }
        self.snapshots.pop();
        Ok(())
    }

    fn preview(&self, entries: Vec<FeedIndicator>) -> PlannedSnapshot {
        let parent = self
            .snapshots
            .last()
            .map(|snapshot| snapshot.manifest.number);
        let number = parent.unwrap_or(0).checked_add(1).expect("version number");
        let content = canonical_content(&entries);
        let content_digest = sha256_hex(content.as_bytes());
        let digest = sha256_hex(manifest_preimage(number, parent, &content_digest).as_bytes());
        PlannedSnapshot {
            manifest: Manifest {
                number,
                parent,
                content_digest,
                digest,
            },
            entries,
        }
    }

    fn ensure_planned(&self, planned: &PlannedSnapshot) -> Result<(), VersionError> {
        let parent = self
            .snapshots
            .last()
            .map(|snapshot| snapshot.manifest.number);
        if parent != planned.manifest.parent {
            return Err(VersionError::Chain);
        }
        for entry in &planned.entries {
            screen_stored(entry, &self.policy).map_err(|_| VersionError::Row)?;
        }
        let seen = planned
            .entries
            .iter()
            .map(|entry| (entry.kind_tag(), entry.value()))
            .collect::<std::collections::BTreeSet<_>>();
        if seen.len() != planned.entries.len() {
            return Err(VersionError::Row);
        }
        let recomputed = self.preview(planned.entries.clone());
        if recomputed.manifest.number != planned.manifest.number
            || recomputed.manifest.content_digest != planned.manifest.content_digest
            || recomputed.manifest.digest != planned.manifest.digest
        {
            return Err(VersionError::Digest);
        }
        Ok(())
    }

    fn push(&mut self, entries: Vec<FeedIndicator>) -> &Snapshot {
        let parent = self
            .snapshots
            .last()
            .map(|snapshot| snapshot.manifest.number);
        let number = parent.unwrap_or(0).checked_add(1).expect("version number");
        let content = canonical_content(&entries);
        let content_digest = sha256_hex(content.as_bytes());
        let digest = sha256_hex(manifest_preimage(number, parent, &content_digest).as_bytes());
        self.snapshots.push(Snapshot {
            manifest: Manifest {
                number,
                parent,
                content_digest,
                digest,
            },
            entries,
        });
        self.snapshots.last().expect("snapshot was just appended")
    }
}

pub(crate) fn canonical_content(entries: &[FeedIndicator]) -> String {
    let mut rows: Vec<&FeedIndicator> = entries.iter().collect();
    rows.sort_by(|left, right| {
        left.kind_tag()
            .cmp(right.kind_tag())
            .then_with(|| left.value().cmp(right.value()))
    });
    let mut out = String::from("mecfeed/1\n");
    for entry in rows {
        let broad = u8::from(entry.broad_explicit());
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{broad}\n",
            entry.kind_tag(),
            entry.value(),
            entry.source(),
            entry.confidence(),
            entry.first_seen(),
            entry.last_seen(),
            entry.expires_at(),
        ));
    }
    out
}

fn manifest_preimage(number: u64, parent: Option<u64>, content_digest: &str) -> String {
    let parent_token = match parent {
        Some(value) => value.to_string(),
        None => "-".to_string(),
    };
    format!("{number}\n{parent_token}\n{content_digest}\n")
}

fn document_from(manifest: &Manifest, entries: &[FeedIndicator]) -> SnapshotDocument {
    SnapshotDocument {
        number: manifest.number,
        parent: manifest.parent,
        content_digest: manifest.content_digest.clone(),
        digest: manifest.digest.clone(),
        entries: entries
            .iter()
            .map(|entry| SnapshotRow {
                kind: entry.kind(),
                value: entry.value().to_string(),
                source: entry.source().to_string(),
                confidence: entry.confidence(),
                first_seen: entry.first_seen(),
                last_seen: entry.last_seen(),
                expires_at: entry.expires_at(),
                broad_explicit: entry.broad_explicit(),
            })
            .collect(),
    }
}

fn rows_to_entries(rows: &[SnapshotRow]) -> Vec<FeedIndicator> {
    rows.iter()
        .map(|row| {
            FeedIndicator::from_row(
                row.kind,
                row.value.clone(),
                row.source.clone(),
                row.confidence,
                row.first_seen,
                row.last_seen,
                row.expires_at,
                row.broad_explicit,
            )
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn testing_digest(
    number: u64,
    parent: Option<u64>,
    entries: &[FeedIndicator],
) -> (String, String) {
    let content_digest = sha256_hex(canonical_content(entries).as_bytes());
    let digest = sha256_hex(manifest_preimage(number, parent, &content_digest).as_bytes());
    (content_digest, digest)
}

fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(Sha256::digest(bytes).as_slice())
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
