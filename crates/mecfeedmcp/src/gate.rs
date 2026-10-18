//! Feed publication gate. A snapshot is written only after the shared
//! change-set coordinator accepts the digest and the planned snapshot still
//! matches.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use mecfeedmcp_core::{
    FeedVersions, IndicatorKind, PlannedSnapshot, Policy, Proposal, ProposedEntry,
    SnapshotDocument, SnapshotRow,
};
use mecmcp_audit::{ActorType, Attribution, Principal, TokenVerifiedFields};
use mecmcp_changeset::{
    ApproverIdentity, ChangeSetState, ChangesetCoordinator, CommitOptions, CommitOutcome,
    CoordinatorError, DeviceTransaction, OperationLimits, RollbackOutcome, RollbackRef,
    mutation_policy_signature,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::store::{self, StoreError};

const ENDPOINT: &str = "https://feed.invalid/mecfeed";
const POLICY_ID: &str = "mecfeed-admission-v1";

/// Why a feed change did not publish.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GateError {
    /// The caller is not a principal the gate can record.
    #[error("principal is not acceptable")]
    Principal,
    /// The change was not admitted.
    #[error("feed change was not admitted")]
    Admission,
    /// No second principal has approved this digest.
    #[error("feed change is not approved")]
    NotApproved,
    /// The approving principal is the one that planned the change.
    #[error("feed change owner cannot approve it")]
    SamePrincipal,
    /// The approver is not a human principal.
    #[error("feed change approver must be a human principal")]
    NotHuman,
    /// The digest does not match the stored plan.
    #[error("feed change digest does not match")]
    Digest,
    /// The feed log moved, or there is nothing to republish.
    #[error("feed change does not match the current feed")]
    Conflict,
    /// The caller is not the principal that planned the change.
    #[error("only the change-set owner can publish or waive it")]
    NotOwner,
    /// The snapshot was not stored.
    #[error("snapshot was not stored")]
    Store,
    /// Feed state could not be locked.
    #[error("feed state is unavailable")]
    State,
}

/// An admitted plan that has not been published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanReceipt {
    /// Change-set id.
    pub change_set_id: String,
    /// Digest the approval must name.
    pub digest: String,
    /// Digest the published snapshot must have.
    pub snapshot_digest: String,
    /// Version number the plan would publish.
    pub version: u64,
}

/// A published snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSnapshot {
    /// Version number.
    pub version: u64,
    /// Snapshot digest.
    pub digest: String,
}

/// One stored snapshot, for a read tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedView {
    /// Version number.
    pub version: u64,
    /// Snapshot digest.
    pub digest: String,
    /// Rows.
    pub entries: Vec<SnapshotRow>,
}

/// Plans, approves, and publishes feed snapshots.
pub struct FeedPublisher {
    coordinator: ChangesetCoordinator,
    inner: Arc<Mutex<Inner>>,
    device: String,
    lab_mode: bool,
    policy_signature: String,
}

struct Inner {
    versions: FeedVersions,
    snapshot_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AddEntry {
    kind: String,
    value: String,
    source: String,
    confidence: u8,
    first_seen: i64,
    last_seen: i64,
    expires_at: Option<i64>,
    allow_broad_prefix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FeedAction {
    Publish {
        snapshot_digest: String,
        entries: Vec<AddEntry>,
    },
    Rollback {
        snapshot_digest: String,
        target: u64,
        expected_latest: u64,
    },
}

struct StagedFeed {
    action: FeedAction,
    document: SnapshotDocument,
}

struct FeedTransaction {
    inner: Arc<Mutex<Inner>>,
    now: i64,
}

impl FeedPublisher {
    /// Open the snapshot directory and the change-set state file.
    ///
    /// # Errors
    ///
    /// Returns an error when a path or the stored log is not acceptable.
    pub fn open(
        snapshot_dir: &Path,
        state_file: &Path,
        policy: Policy,
        device: &str,
        lab_mode: bool,
        approval_ttl: Duration,
    ) -> Result<Self, GateError> {
        check_principal(device)?;
        if !state_file.is_absolute() {
            return Err(GateError::Store);
        }
        let (snapshot_dir, versions) = store::open_dir(snapshot_dir, policy).map_err(map_store)?;
        let limits = OperationLimits {
            max_actions_per_set: 100,
            ..OperationLimits::default()
        };
        let coordinator =
            ChangesetCoordinator::load(Some(state_file), limits, approval_ttl, lab_mode)
                .map_err(|_| GateError::Store)?;
        Ok(Self {
            coordinator,
            inner: Arc::new(Mutex::new(Inner {
                versions,
                snapshot_dir,
            })),
            device: device.to_string(),
            lab_mode,
            policy_signature: mutation_policy_signature(POLICY_ID),
        })
    }

    /// Whether lab mode records a waiver instead of a second principal.
    #[must_use]
    pub fn lab_mode(&self) -> bool {
        self.lab_mode
    }

    /// Tenant name this publisher records on each change set.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Validate `proposal` and store it. Nothing is published.
    ///
    /// # Errors
    ///
    /// Returns an error when the principal or the proposal is not acceptable.
    pub async fn plan(
        &self,
        owner: &str,
        proposal: Proposal,
        now: i64,
    ) -> Result<PlanReceipt, GateError> {
        check_principal(owner)?;
        let (fingerprint, planned, action) = {
            let inner = self.lock()?;
            let planned = inner.versions.plan(&proposal, now).map_err(map_version)?;
            let action = FeedAction::Publish {
                snapshot_digest: planned.digest().to_string(),
                entries: proposal.entries.iter().map(add_entry).collect(),
            };
            (inner.versions.state_fingerprint(), planned, action)
        };
        self.store_plan(owner, vec![action], fingerprint, planned)
            .await
    }

    /// Store a rollback plan. Nothing is published.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is not an earlier snapshot.
    pub async fn stage_rollback(
        &self,
        owner: &str,
        target: u64,
        expected_latest: u64,
        now: i64,
    ) -> Result<PlanReceipt, GateError> {
        check_principal(owner)?;
        let (fingerprint, planned, action) = {
            let inner = self.lock()?;
            let planned = inner
                .versions
                .plan_rollback(target, expected_latest, now)
                .map_err(map_version)?;
            let action = FeedAction::Rollback {
                snapshot_digest: planned.digest().to_string(),
                target,
                expected_latest,
            };
            (inner.versions.state_fingerprint(), planned, action)
        };
        self.store_plan(owner, vec![action], fingerprint, planned)
            .await
    }

    /// Record a human approval of `digest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the principal, digest, or actor is not acceptable.
    pub async fn approve(
        &self,
        approver: &str,
        human: bool,
        change_set_id: &str,
        digest: &str,
    ) -> Result<(), GateError> {
        check_principal(approver)?;
        if !human {
            return Err(GateError::NotHuman);
        }
        let identity = ApproverIdentity::TokenAsserted {
            principal: approver.to_string(),
            actor_type: ActorType::Human,
        };
        self.coordinator
            .approve_change_set(
                change_set_id.to_string(),
                self.device.clone(),
                &identity,
                digest.to_string(),
            )
            .await
            .map_err(map_coordinator)?;
        Ok(())
    }

    /// Record a lab-mode waiver. Refused when lab mode is off.
    ///
    /// # Errors
    ///
    /// Returns an error when lab mode is off or the digest does not match.
    pub async fn waive(
        &self,
        owner: &str,
        change_set_id: &str,
        digest: &str,
    ) -> Result<(), GateError> {
        check_principal(owner)?;
        if !self.lab_mode {
            return Err(GateError::NotApproved);
        }
        self.coordinator
            .waive_approval(
                change_set_id.to_string(),
                self.device.clone(),
                owner.to_string(),
                digest.to_string(),
            )
            .await
            .map_err(map_coordinator)?;
        Ok(())
    }

    /// Publish an approved change when the snapshot digest still matches.
    ///
    /// # Errors
    ///
    /// Returns an error and writes nothing when approval or the digest fails.
    pub async fn apply(
        &self,
        owner: &str,
        change_set_id: &str,
        digest: &str,
        now: i64,
    ) -> Result<PublishedSnapshot, GateError> {
        check_principal(owner)?;
        let fingerprint = self.lock()?.versions.state_fingerprint();
        let transaction = FeedTransaction {
            inner: Arc::clone(&self.inner),
            now,
        };
        let attribution = attribution_for(owner);
        let cancel = CancellationToken::new();
        let applied = self
            .coordinator
            .apply_change_set(
                change_set_id.to_string(),
                self.device.clone(),
                ENDPOINT.to_string(),
                owner.to_string(),
                digest.to_string(),
                fingerprint.clone(),
                &transaction,
                "publish",
                Some("snapshot"),
                Some("local".to_string()),
                &attribution,
                &cancel,
            )
            .await
            .map_err(map_coordinator)?;
        if applied.recorded_state != ChangeSetState::Applied {
            return Err(GateError::Store);
        }
        self.coordinator
            .validate_operation(
                &applied.operation_id,
                &self.device,
                owner,
                &applied.after_fingerprint,
                &transaction,
                &applied.staged,
                &cancel,
            )
            .await
            .map_err(map_coordinator)?;
        let outcome = self
            .coordinator
            .commit_operation(
                &applied.operation_id,
                &self.device,
                owner,
                &applied.after_fingerprint,
                &self.policy_signature,
                &transaction,
                &applied.staged,
                &attribution,
                &CommitOptions::default(),
                &cancel,
            )
            .await
            .map_err(map_coordinator)?;
        match outcome {
            CommitOutcome::Reconciled {
                succeeded: true, ..
            } => Ok(PublishedSnapshot {
                version: applied.staged.document.number,
                digest: applied.staged.document.digest,
            }),
            CommitOutcome::Indeterminate { .. } => Err(GateError::Store),
            _ => Err(GateError::Store),
        }
    }

    /// Latest published snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the feed lock is unavailable.
    pub fn latest(&self) -> Result<Option<FeedView>, GateError> {
        let inner = self.lock()?;
        Ok(inner.versions.latest().map(|snapshot| FeedView {
            version: snapshot.manifest().number(),
            digest: snapshot.manifest().digest().to_string(),
            entries: inner
                .versions
                .document(snapshot.manifest().number())
                .map(|document| document.entries)
                .unwrap_or_default(),
        }))
    }

    /// Published versions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error when the feed lock is unavailable.
    pub fn history(&self) -> Result<Vec<FeedView>, GateError> {
        let inner = self.lock()?;
        let mut views = Vec::new();
        let mut number = 1_u64;
        while let Some(document) = inner.versions.document(number) {
            views.push(FeedView {
                version: document.number,
                digest: document.digest,
                entries: document.entries,
            });
            number = number.saturating_add(1);
        }
        Ok(views)
    }

    async fn store_plan(
        &self,
        owner: &str,
        actions: Vec<FeedAction>,
        fingerprint: String,
        planned: PlannedSnapshot,
    ) -> Result<PlanReceipt, GateError> {
        let output = self
            .coordinator
            .create_change_set(
                self.device.clone(),
                actions,
                owner.to_string(),
                fingerprint,
                self.policy_signature.clone(),
                None,
            )
            .await
            .map_err(map_coordinator)?;
        Ok(PlanReceipt {
            change_set_id: output.change_set_id,
            digest: output.digest,
            snapshot_digest: planned.digest().to_string(),
            version: planned.number(),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, GateError> {
        self.inner.lock().map_err(|_| GateError::State)
    }
}

#[async_trait]
impl DeviceTransaction for FeedTransaction {
    type Action = FeedAction;
    type Staged = StagedFeed;
    type Diff = String;
    type Validation = bool;
    type Error = TxError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let inner = self.inner.lock().map_err(|_| TxError::State)?;
        Ok(inner.versions.state_fingerprint())
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let action = one_action(actions)?;
        let inner = self.inner.lock().map_err(|_| TxError::State)?;
        let planned = plan_action(&inner.versions, action, self.now)?;
        if planned.digest() != action_digest(action) {
            return Err(TxError::Digest);
        }
        Ok(StagedFeed {
            action: action.clone(),
            document: planned.document(),
        })
    }

    async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(String::new())
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let inner = self.inner.lock().map_err(|_| TxError::State)?;
        let planned = plan_action(&inner.versions, &staged.action, self.now)?;
        if planned.digest() != staged.document.digest {
            return Err(TxError::Digest);
        }
        Ok(true)
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        let mut inner = self.inner.lock().map_err(|_| TxError::State)?;
        let planned = plan_action(&inner.versions, &staged.action, self.now)?;
        if planned.digest() != staged.document.digest {
            return Err(TxError::Digest);
        }
        let document = planned.document();
        store::write_snapshot_file(&inner.snapshot_dir, &document).map_err(|_| TxError::Store)?;
        if let Err(error) = inner.versions.commit_planned(&planned, self.now) {
            let _ = store::remove_version(&inner.snapshot_dir, document.number);
            return Err(match error {
                mecfeedmcp_core::VersionError::Digest => TxError::Digest,
                _ => TxError::Store,
            });
        }
        if store::set_current(&inner.snapshot_dir, document.number).is_err() {
            let _ = inner.versions.discard_latest_if_digest(&document.digest);
            let _ = store::remove_version(&inner.snapshot_dir, document.number);
            return Err(TxError::Store);
        }
        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: None,
            details: None,
        })
    }

    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Err(TxError::Unsupported)
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(TxError::Unsupported)
    }
}

#[derive(Debug, Error)]
enum TxError {
    #[error("feed change was not admitted")]
    Admission,
    #[error("snapshot digest does not match")]
    Digest,
    #[error("feed state is unavailable")]
    State,
    #[error("snapshot was not stored")]
    Store,
    #[error("this rollback path is not used")]
    Unsupported,
}

fn one_action(actions: &[FeedAction]) -> Result<&FeedAction, TxError> {
    match actions {
        [action] => Ok(action),
        _ => Err(TxError::Admission),
    }
}

fn action_digest(action: &FeedAction) -> &str {
    match action {
        FeedAction::Publish {
            snapshot_digest, ..
        }
        | FeedAction::Rollback {
            snapshot_digest, ..
        } => snapshot_digest,
    }
}

fn plan_action(
    versions: &FeedVersions,
    action: &FeedAction,
    now: i64,
) -> Result<PlannedSnapshot, TxError> {
    match action {
        FeedAction::Publish { entries, .. } => {
            let proposal = Proposal {
                entries: proposed_entries(entries)?,
            };
            versions
                .plan(&proposal, now)
                .map_err(|_| TxError::Admission)
        }
        FeedAction::Rollback {
            target,
            expected_latest,
            ..
        } => versions
            .plan_rollback(*target, *expected_latest, now)
            .map_err(|_| TxError::Admission),
    }
}

fn kind_name(kind: IndicatorKind) -> &'static str {
    match kind {
        IndicatorKind::Ip => "ip",
        IndicatorKind::Cidr => "cidr",
        IndicatorKind::Domain => "domain",
    }
}

fn add_entry(entry: &ProposedEntry) -> AddEntry {
    AddEntry {
        kind: kind_name(entry.kind).to_string(),
        value: entry.value.clone(),
        source: entry.source.clone(),
        confidence: entry.confidence,
        first_seen: entry.first_seen,
        last_seen: entry.last_seen,
        expires_at: entry.expires_at,
        allow_broad_prefix: entry.allow_broad_prefix,
    }
}

fn proposed_entries(entries: &[AddEntry]) -> Result<Vec<ProposedEntry>, TxError> {
    let mut proposed = Vec::with_capacity(entries.len());
    for entry in entries {
        let kind = parse_kind(&entry.kind).ok_or(TxError::Admission)?;
        proposed.push(ProposedEntry {
            kind,
            value: entry.value.clone(),
            source: entry.source.clone(),
            confidence: entry.confidence,
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            expires_at: entry.expires_at,
            allow_broad_prefix: entry.allow_broad_prefix,
        });
    }
    Ok(proposed)
}

fn check_principal(value: &str) -> Result<(), GateError> {
    if value.is_empty() || value.contains('|') || value.len() > 128 {
        return Err(GateError::Principal);
    }
    Ok(())
}

fn map_store(error: StoreError) -> GateError {
    match error {
        StoreError::Digest => GateError::Digest,
        _ => GateError::Store,
    }
}

fn map_version(error: mecfeedmcp_core::VersionError) -> GateError {
    match error {
        mecfeedmcp_core::VersionError::Admit(_) => GateError::Admission,
        mecfeedmcp_core::VersionError::Digest => GateError::Digest,
        mecfeedmcp_core::VersionError::Stale { .. }
        | mecfeedmcp_core::VersionError::NothingToRollBack
        | mecfeedmcp_core::VersionError::Empty
        | mecfeedmcp_core::VersionError::Chain => GateError::Conflict,
        _ => GateError::Admission,
    }
}

fn map_coordinator(error: CoordinatorError) -> GateError {
    let message = error.message();
    if message.contains("cannot approve their own plan")
        || message.contains("approved by its own owner")
    {
        return GateError::SamePrincipal;
    }
    if message.contains("must be a human") {
        return GateError::NotHuman;
    }
    if message.contains("only the change-set owner")
        || message.contains("only the principal that created")
    {
        return GateError::NotOwner;
    }
    if message.contains("requires approval") || message.contains("waiver requires lab mode") {
        return GateError::NotApproved;
    }
    if error.field() == "expected_digest" || message.contains("digest") {
        return GateError::Digest;
    }
    if message.contains("fingerprint") || message.contains("no such") {
        return GateError::Conflict;
    }
    GateError::Store
}

fn attribution_for(owner: &str) -> Attribution {
    Attribution {
        principal: Principal::Token(owner.to_string()),
        actor_type: ActorType::Human,
        agent: None,
        on_behalf_of: None,
        change_ref: None,
        request_id: Uuid::new_v4(),
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    }
}

/// Parse a tool's indicator kind. Unknown kinds are refused.
pub(crate) fn parse_kind(kind: &str) -> Option<IndicatorKind> {
    match kind {
        "ip" => Some(IndicatorKind::Ip),
        "cidr" => Some(IndicatorKind::Cidr),
        "domain" => Some(IndicatorKind::Domain),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use mecfeedmcp_core::{IndicatorKind, Limits, Proposal, ProposedEntry};

    use super::{FeedPublisher, GateError, Policy};

    const NOW: i64 = 1_700_000_000;
    const WEEK: i64 = 7 * 24 * 60 * 60;

    struct Fixture {
        _dir: tempfile::TempDir,
        snapshots: std::path::PathBuf,
        state: std::path::PathBuf,
    }

    fn policy() -> Policy {
        Policy::try_new(
            Vec::new(),
            Vec::new(),
            std::iter::empty::<&str>(),
            Limits::default(),
        )
        .expect("policy")
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        Fixture {
            snapshots: dir.path().join("snapshots"),
            state: dir.path().join("changeset-state.json"),
            _dir: dir,
        }
    }

    fn open(fix: &Fixture, lab: bool) -> FeedPublisher {
        FeedPublisher::open(
            &fix.snapshots,
            &fix.state,
            policy(),
            "lab",
            lab,
            Duration::from_secs(900),
        )
        .expect("open")
    }

    fn one(value: &str) -> Proposal {
        Proposal {
            entries: vec![ProposedEntry {
                kind: IndicatorKind::Ip,
                value: value.to_string(),
                source: "lab".to_string(),
                confidence: 50,
                first_seen: NOW,
                last_seen: NOW,
                expires_at: Some(NOW + WEEK),
                allow_broad_prefix: false,
            }],
        }
    }

    fn other_digest() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    #[tokio::test]
    async fn approved_apply_reloads_the_same_digest() {
        let fix = fixture();
        let digest = {
            let publisher = open(&fix, false);
            let plan = publisher
                .plan("alice", one("1.0.0.1"), NOW)
                .await
                .expect("plan");
            publisher
                .approve("bob", true, &plan.change_set_id, &plan.digest)
                .await
                .expect("approve");
            let published = publisher
                .apply("alice", &plan.change_set_id, &plan.digest, NOW)
                .await
                .expect("apply");
            assert_eq!(published.digest, plan.snapshot_digest);
            let latest = publisher.latest().expect("lock").expect("latest");
            assert_eq!(latest.digest, published.digest);
            assert_eq!(latest.entries[0].value, "1.0.0.1");
            published.digest
        };
        let publisher = open(&fix, false);
        let latest = publisher.latest().expect("lock").expect("reloaded");
        assert_eq!(latest.digest, digest);
    }

    #[tokio::test]
    async fn apply_without_approval_writes_nothing() {
        let fix = fixture();
        let publisher = open(&fix, false);
        let plan = publisher
            .plan("alice", one("1.0.0.1"), NOW)
            .await
            .expect("plan");
        let err = publisher
            .apply("alice", &plan.change_set_id, &plan.digest, NOW)
            .await
            .expect_err("apply");
        assert_eq!(err, GateError::NotApproved);
        assert!(publisher.latest().expect("lock").is_none());
        assert!(!fix.snapshots.join("current").exists());
    }

    #[tokio::test]
    async fn wrong_digest_writes_nothing() {
        let fix = fixture();
        let publisher = open(&fix, false);
        let plan = publisher
            .plan("alice", one("1.0.0.1"), NOW)
            .await
            .expect("plan");
        publisher
            .approve("bob", true, &plan.change_set_id, &plan.digest)
            .await
            .expect("approve");
        let err = publisher
            .apply("alice", &plan.change_set_id, &other_digest(), NOW)
            .await
            .expect_err("apply");
        assert_eq!(err, GateError::Digest);
        assert!(publisher.latest().expect("lock").is_none());
        assert!(!fix.snapshots.join("current").exists());
    }

    #[tokio::test]
    async fn self_approve_is_refused() {
        let fix = fixture();
        let publisher = open(&fix, false);
        let plan = publisher
            .plan("alice", one("1.0.0.1"), NOW)
            .await
            .expect("plan");
        let err = publisher
            .approve("alice", true, &plan.change_set_id, &plan.digest)
            .await
            .expect_err("approve");
        assert_eq!(err, GateError::SamePrincipal);
        assert!(publisher.latest().expect("lock").is_none());
    }

    #[tokio::test]
    async fn lab_waiver_then_apply_publishes() {
        let fix = fixture();
        let publisher = open(&fix, true);
        let plan = publisher
            .plan("alice", one("1.0.0.1"), NOW)
            .await
            .expect("plan");
        publisher
            .waive("alice", &plan.change_set_id, &plan.digest)
            .await
            .expect("waive");
        let published = publisher
            .apply("alice", &plan.change_set_id, &plan.digest, NOW)
            .await
            .expect("apply");
        assert_eq!(published.digest, plan.snapshot_digest);
        assert!(fix.snapshots.join("current").is_file());
    }

    #[tokio::test]
    async fn tampered_snapshot_fails_open() {
        let fix = fixture();
        let digest = {
            let publisher = open(&fix, true);
            let plan = publisher
                .plan("alice", one("1.0.0.1"), NOW)
                .await
                .expect("plan");
            publisher
                .waive("alice", &plan.change_set_id, &plan.digest)
                .await
                .expect("waive");
            publisher
                .apply("alice", &plan.change_set_id, &plan.digest, NOW)
                .await
                .expect("apply")
                .digest
        };
        let path = fix.snapshots.join("versions/1/snapshot.json");
        let text = fs::read_to_string(&path).expect("snapshot");
        let tampered = text.replacen(&digest, &other_digest(), 1);
        assert_ne!(tampered, text);
        fs::write(&path, tampered).expect("write");
        match FeedPublisher::open(
            &fix.snapshots,
            &fix.state,
            policy(),
            "lab",
            false,
            Duration::from_secs(900),
        ) {
            Err(err) => assert_eq!(err, GateError::Digest),
            Ok(_) => panic!("open accepted a tampered snapshot"),
        }
    }

    #[tokio::test]
    async fn rollback_publishes_the_earlier_rows() {
        let fix = fixture();
        let publisher = open(&fix, true);
        let first = publisher
            .plan("alice", one("1.0.0.1"), NOW)
            .await
            .expect("plan 1");
        publisher
            .waive("alice", &first.change_set_id, &first.digest)
            .await
            .expect("waive 1");
        publisher
            .apply("alice", &first.change_set_id, &first.digest, NOW)
            .await
            .expect("apply 1");
        let second = publisher
            .plan("alice", one("1.0.0.2"), NOW)
            .await
            .expect("plan 2");
        publisher
            .waive("alice", &second.change_set_id, &second.digest)
            .await
            .expect("waive 2");
        publisher
            .apply("alice", &second.change_set_id, &second.digest, NOW)
            .await
            .expect("apply 2");
        let rollback = publisher
            .stage_rollback("alice", 1, 2, NOW)
            .await
            .expect("rollback");
        publisher
            .waive("alice", &rollback.change_set_id, &rollback.digest)
            .await
            .expect("waive rollback");
        let published = publisher
            .apply("alice", &rollback.change_set_id, &rollback.digest, NOW)
            .await
            .expect("apply rollback");
        assert_eq!(published.version, 3);
        let latest = publisher.latest().expect("lock").expect("latest");
        assert_eq!(latest.version, 3);
        assert_eq!(latest.entries.len(), 1);
        assert_eq!(latest.entries[0].value, "1.0.0.1");
        assert_eq!(
            fs::read_to_string(fix.snapshots.join("current"))
                .expect("current")
                .trim(),
            "3"
        );
    }
}
