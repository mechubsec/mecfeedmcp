//! MCP tools for planning, approving, and publishing feed snapshots.
//!
//! The caller principal comes from the authenticated token. Tool arguments
//! do not name an approver. A write with no caller is refused.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mecfeedmcp_core::{IndicatorKind, Proposal, ProposedEntry, SnapshotRow};
use mecmcp_audit::{Attribution, AuditScope};
use mecmcp_auth::{ActorType, CallerCtx, NoGrant};
use rmcp::{
    ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, Extensions, Implementation, ServerCapabilities, ServerConfig,
    },
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::gate::{self, FeedPublisher, FeedView};
use crate::misp::{MappedIndicator, MispError, MispPage, MispQuery, MispSource};

/// Unwrap an authorization result, or audit a denial and return it.
macro_rules! admit {
    ($audit:ident, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(denial) => {
                $audit.deny("not_authorized");
                return Ok(denial);
            }
        }
    };
}

/// Unwrap a gate result, or audit the failure and return its fixed text.
macro_rules! gated {
    ($audit:ident, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => {
                $audit.fail(&error);
                return Ok(gate_text(error));
            }
        }
    };
}

/// Unwrap a request-validation result, or audit the failure and return it.
macro_rules! valid {
    ($audit:ident, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(refusal) => {
                $audit.fail("request is not acceptable");
                return Ok(refusal);
            }
        }
    };
}

/// Tools this server registers.
pub const KNOWN_TOOLS: &[&str] = &[
    "get_feed",
    "get_feed_history",
    "get_feed_change",
    "list_indicators",
    "search_indicators",
    "plan_feed_change",
    "approve_feed_change",
    "apply_feed_change",
    "rollback_feed",
];

/// Tools a wildcard tool scope does not grant.
pub const WRITE_TOOLS: &[&str] = &[
    "plan_feed_change",
    "approve_feed_change",
    "apply_feed_change",
    "rollback_feed",
];

/// MCP handler bound to one feed publisher.
#[derive(Clone)]
pub struct FeedHandler {
    publisher: Arc<FeedPublisher>,
    misp: Option<Arc<dyn MispSource>>,
    tool_router: ToolRouter<Self>,
}

impl FeedHandler {
    /// Register the feed tools on `publisher` with no MISP source.
    #[must_use]
    pub fn new(publisher: Arc<FeedPublisher>) -> Self {
        Self::with_misp(publisher, None)
    }

    /// Register the feed tools, with an optional read-only MISP source.
    #[must_use]
    pub fn with_misp(publisher: Arc<FeedPublisher>, misp: Option<Arc<dyn MispSource>>) -> Self {
        Self {
            publisher,
            misp,
            tool_router: Self::tool_router(),
        }
    }

    fn caller(extensions: &Extensions) -> Option<CallerCtx<NoGrant>> {
        extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<CallerCtx<NoGrant>>())
            .cloned()
    }

    /// Attribution for `caller`, or the unauthenticated one when absent.
    fn attribution(
        caller: Option<&CallerCtx<NoGrant>>,
        change_set_id: Option<&str>,
    ) -> Attribution {
        let mut attribution = caller.map_or_else(Attribution::stdio, Attribution::from_caller);
        if let Some(id) = change_set_id {
            attribution.with_change_set(id, None);
        }
        attribution
    }

    /// Open the audit scope for one tool call. The feed is the audited device.
    fn scope(
        &self,
        attribution: &Attribution,
        tool: &'static str,
        action: &'static str,
    ) -> AuditScope {
        AuditScope::new(
            attribution.clone(),
            tool,
            action,
            vec![self.publisher.device().to_string()],
        )
    }

    #[allow(clippy::result_large_err)]
    fn authorize(
        &self,
        extensions: &Extensions,
        tool: &'static str,
        write: bool,
    ) -> Result<Option<CallerCtx<NoGrant>>, CallToolResult> {
        let Some(caller) = Self::caller(extensions) else {
            if write {
                return Err(error_result(
                    "a feed write needs an authenticated principal",
                ));
            }
            return Ok(None);
        };
        if !caller.tools.allows_tool(tool, WRITE_TOOLS) {
            return Err(error_result("token is not authorized for this tool"));
        }
        if !caller.devices.allows(self.publisher.device()) {
            return Err(error_result("token is not authorized for this feed"));
        }
        Ok(Some(caller))
    }

    #[allow(clippy::result_large_err)]
    fn require_writer(
        &self,
        extensions: &Extensions,
        tool: &'static str,
    ) -> Result<CallerCtx<NoGrant>, CallToolResult> {
        match self.authorize(extensions, tool, true)? {
            Some(caller) => Ok(caller),
            None => Err(error_result(
                "a feed write needs an authenticated principal",
            )),
        }
    }

    async fn misp_search(&self, query: &MispQuery) -> Result<MispPage, MispError> {
        match &self.misp {
            Some(source) => source.search(query).await,
            None => Err(MispError::Unconfigured),
        }
    }
}

/// Arguments for [`FeedHandler::get_feed`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetFeedInput {
    /// Snapshot version. Absent reads the latest snapshot.
    #[serde(default)]
    pub version: Option<u64>,
}

/// No arguments.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

/// One proposed indicator.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanEntryInput {
    /// `ip`, `cidr`, or `domain`.
    pub kind: String,
    /// Indicator text. Admission stores the canonical form.
    pub value: String,
    /// Origin label.
    pub source: String,
    /// Confidence from 0 to 100.
    pub confidence: u8,
    /// First-seen time, as Unix seconds.
    pub first_seen: i64,
    /// Last-seen time, as Unix seconds.
    pub last_seen: i64,
    /// Expiry, as Unix seconds. Absent uses the policy default.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Ask to keep a prefix shorter than the policy minimum.
    #[serde(default)]
    pub allow_broad_prefix: bool,
}

/// Arguments for [`FeedHandler::plan_feed_change`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanFeedChangeInput {
    /// Proposed entries. The set is admitted whole or not at all.
    pub entries: Vec<PlanEntryInput>,
}

/// Arguments that name one stored change-set digest.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetDigestInput {
    /// Change-set id returned by the plan.
    pub change_set_id: String,
    /// Digest returned by the plan.
    pub digest: String,
}

/// Arguments that name one stored change set.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetIdInput {
    /// Change-set id returned by the plan.
    pub change_set_id: String,
}

/// Arguments for [`FeedHandler::rollback_feed`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackFeedInput {
    /// Snapshot version to republish.
    pub target: u64,
    /// Latest version the caller saw.
    pub expected_latest: u64,
}

/// Arguments for [`FeedHandler::list_indicators`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListIndicatorsInput {
    /// `ip`, `cidr`, or `domain`. Applied after the fetch. Absent returns all three.
    #[serde(default)]
    pub kind: Option<String>,
    /// Maximum mapped rows. Absent uses the policy entry cap.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for [`FeedHandler::search_indicators`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchIndicatorsInput {
    /// Value match sent to MISP restSearch.
    pub query: String,
    /// `ip`, `cidr`, or `domain`. Applied after the fetch. Absent returns all three.
    #[serde(default)]
    pub kind: Option<String>,
    /// Maximum mapped rows. Absent uses the policy entry cap.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[tool_router]
impl FeedHandler {
    /// Read one published snapshot.
    #[tool(
        name = "get_feed",
        description = "Read one published feed snapshot by version, or the latest snapshot when version is omitted"
    )]
    async fn get_feed(
        &self,
        Parameters(input): Parameters<GetFeedInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(Self::caller(&extensions).as_ref(), None);
        let mut audit = self.scope(&attribution, "get_feed", "read");
        admit!(audit, self.authorize(&extensions, "get_feed", false));
        let view = match input.version {
            Some(number) => gated!(audit, self.publisher.history())
                .into_iter()
                .find(|view| view.version == number),
            None => gated!(audit, self.publisher.latest()),
        };
        let Some(view) = view else {
            audit.fail("snapshot was not found");
            return error("snapshot was not found");
        };
        audit.succeed();
        success(&view_json(&view))
    }

    /// Read published snapshots, oldest first.
    #[tool(
        name = "get_feed_history",
        description = "List published feed snapshots, oldest first"
    )]
    async fn get_feed_history(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(Self::caller(&extensions).as_ref(), None);
        let mut audit = self.scope(&attribution, "get_feed_history", "read");
        admit!(
            audit,
            self.authorize(&extensions, "get_feed_history", false)
        );
        let views = gated!(audit, self.publisher.history());
        audit.succeed();
        success(&json!({
            "snapshots": views.iter().map(view_json).collect::<Vec<_>>(),
        }))
    }

    /// List mapped MISP indicators. Does not plan or publish.
    #[tool(
        name = "list_indicators",
        description = "List mapped MISP indicators of ip, cidr, and domain kinds. Kind is applied after the fetch. truncated is true when the upstream page is full. Read-only. Does not plan or publish a snapshot"
    )]
    async fn list_indicators(
        &self,
        Parameters(input): Parameters<ListIndicatorsInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(Self::caller(&extensions).as_ref(), None);
        let mut audit = self.scope(&attribution, "list_indicators", "read");
        admit!(audit, self.authorize(&extensions, "list_indicators", false));
        let query = valid!(
            audit,
            misp_query(None, input.kind.as_deref(), input.limit, &self.publisher)
        );
        let page = match self.misp_search(&query).await {
            Ok(page) => page,
            Err(failed) => {
                audit.fail(&failed);
                return error(&failed.to_string());
            }
        };
        audit.succeed();
        success(&page_json(&page))
    }

    /// Search mapped MISP indicators by value. Does not plan or publish.
    #[tool(
        name = "search_indicators",
        description = "Search mapped MISP indicators by value. Kind is applied after the fetch. truncated is true when the upstream page is full. Read-only. Does not plan or publish a snapshot"
    )]
    async fn search_indicators(
        &self,
        Parameters(input): Parameters<SearchIndicatorsInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(Self::caller(&extensions).as_ref(), None);
        let mut audit = self.scope(&attribution, "search_indicators", "read");
        admit!(
            audit,
            self.authorize(&extensions, "search_indicators", false)
        );
        let query = valid!(
            audit,
            misp_query(
                Some(input.query),
                input.kind.as_deref(),
                input.limit,
                &self.publisher
            )
        );
        let page = match self.misp_search(&query).await {
            Ok(page) => page,
            Err(failed) => {
                audit.fail(&failed);
                return error(&failed.to_string());
            }
        };
        audit.succeed();
        success(&page_json(&page))
    }

    /// Read a stored change set, for the approver.
    #[tool(
        name = "get_feed_change",
        description = "Read a stored feed change set without changing it: the planned rows, the rollback target, the snapshot and change-set digests, the owner, the approval expiry, and the rows added and removed against the current snapshot. The approver reads this before approve_feed_change"
    )]
    async fn get_feed_change(
        &self,
        Parameters(input): Parameters<ChangeSetIdInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(
            Self::caller(&extensions).as_ref(),
            Some(&input.change_set_id),
        );
        let mut audit = self.scope(&attribution, "get_feed_change", "read");
        admit!(audit, self.authorize(&extensions, "get_feed_change", false));
        let now = valid!(audit, unix_now());
        let change = gated!(
            audit,
            self.publisher.inspect(&input.change_set_id, now).await
        );
        audit.meta("digest", change.digest.clone());
        audit.succeed();
        success(&json!({
            "change_set_id": input.change_set_id,
            "op": change.op,
            "owner": change.owner,
            "state": change.state,
            "digest": change.digest,
            "snapshot_digest": change.snapshot_digest,
            "version": change.version,
            "rollback_target": change.rollback_target,
            "approval_expires_at": change.expires_at_unix,
            "entries": change.entries.iter().map(row_json).collect::<Vec<_>>(),
            "added": change.added.iter().map(row_json).collect::<Vec<_>>(),
            "removed": change.removed.iter().map(row_json).collect::<Vec<_>>(),
        }))
    }

    /// Admit a proposal and store its digest. Nothing is published.
    #[tool(
        name = "plan_feed_change",
        description = "Admit a feed proposal and store its digest. Does not publish a snapshot"
    )]
    async fn plan_feed_change(
        &self,
        Parameters(input): Parameters<PlanFeedChangeInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(Self::caller(&extensions).as_ref(), None);
        let mut audit = self.scope(&attribution, "plan_feed_change", "plan");
        let caller = admit!(audit, self.require_writer(&extensions, "plan_feed_change"));
        let now = valid!(audit, unix_now());
        let proposal = valid!(audit, proposal_from(&input.entries));
        let receipt = gated!(
            audit,
            self.publisher.plan(&caller.token_name, proposal, now).await
        );
        audit.meta("change_set_id", receipt.change_set_id.clone());
        audit.meta("digest", receipt.digest.clone());
        audit.meta("version", receipt.version);
        audit.succeed();
        success(&json!({
            "change_set_id": receipt.change_set_id,
            "digest": receipt.digest,
            "snapshot_digest": receipt.snapshot_digest,
            "version": receipt.version,
        }))
    }

    /// Record approval of one stored digest.
    ///
    /// Outside lab mode the caller must be a different human principal.
    /// In lab mode the owner records a waiver.
    #[tool(
        name = "approve_feed_change",
        description = "Approve one stored feed digest. Read get_feed_change for the change set first: approve only rows you have read. Production requires a different human principal. Lab mode records a waiver by the owner"
    )]
    async fn approve_feed_change(
        &self,
        Parameters(input): Parameters<ChangeSetDigestInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let waive = self.publisher.lab_mode();
        let attribution = Self::attribution(
            Self::caller(&extensions).as_ref(),
            Some(&input.change_set_id),
        );
        let mut audit = self.scope(
            &attribution,
            "approve_feed_change",
            if waive { "waive" } else { "approve" },
        );
        audit.meta("change_set_id", input.change_set_id.clone());
        audit.meta("digest", input.digest.clone());
        let caller = admit!(
            audit,
            self.require_writer(&extensions, "approve_feed_change")
        );
        let result = if waive {
            self.publisher
                .waive(&caller.token_name, &input.change_set_id, &input.digest)
                .await
        } else {
            self.publisher
                .approve(
                    &caller.token_name,
                    caller.actor_type == ActorType::Human,
                    &input.change_set_id,
                    &input.digest,
                )
                .await
        };
        gated!(audit, result);
        audit.succeed();
        success(&json!({ "approved": true }))
    }

    /// Publish one approved digest.
    #[tool(
        name = "apply_feed_change",
        description = "Publish the snapshot bound to an approved feed digest. An unapproved or different digest is not written"
    )]
    async fn apply_feed_change(
        &self,
        Parameters(input): Parameters<ChangeSetDigestInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(
            Self::caller(&extensions).as_ref(),
            Some(&input.change_set_id),
        );
        let mut audit = self.scope(&attribution, "apply_feed_change", "apply");
        audit.meta("change_set_id", input.change_set_id.clone());
        audit.meta("digest", input.digest.clone());
        let caller = admit!(audit, self.require_writer(&extensions, "apply_feed_change"));
        let now = valid!(audit, unix_now());
        let published = gated!(
            audit,
            self.publisher
                .apply(
                    &caller.token_name,
                    &attribution,
                    &input.change_set_id,
                    &input.digest,
                    now,
                )
                .await
        );
        audit.meta("published_version", published.version);
        audit.meta("snapshot_digest", published.digest.clone());
        audit.succeed();
        success(&json!({
            "version": published.version,
            "digest": published.digest,
        }))
    }

    /// Plan a republish of an earlier snapshot. Apply publishes it.
    #[tool(
        name = "rollback_feed",
        description = "Plan a republish of an earlier snapshot. Nothing is published until apply_feed_change"
    )]
    async fn rollback_feed(
        &self,
        Parameters(input): Parameters<RollbackFeedInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let attribution = Self::attribution(Self::caller(&extensions).as_ref(), None);
        let mut audit = self.scope(&attribution, "rollback_feed", "rollback");
        audit.meta("target", input.target);
        let caller = admit!(audit, self.require_writer(&extensions, "rollback_feed"));
        let now = valid!(audit, unix_now());
        let receipt = gated!(
            audit,
            self.publisher
                .stage_rollback(&caller.token_name, input.target, input.expected_latest, now)
                .await
        );
        audit.meta("change_set_id", receipt.change_set_id.clone());
        audit.meta("digest", receipt.digest.clone());
        audit.succeed();
        success(&json!({
            "change_set_id": receipt.change_set_id,
            "digest": receipt.digest,
            "snapshot_digest": receipt.snapshot_digest,
            "version": receipt.version,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FeedHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mecfeedmcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "mecfeedmcp publishes versioned threat-intel feed snapshots. \
                 list_indicators and search_indicators read mapped MISP indicators; kind is applied after the fetch; they do not plan or publish. \
                 plan_feed_change admits a proposal and stores a digest. \
                 get_feed_change shows the approver the planned rows and the diff against the current snapshot; \
                 the approver reads it before approve_feed_change. \
                 approve_feed_change records a different human principal, or a lab-mode waiver by the owner. \
                 apply_feed_change publishes that exact digest. \
                 rollback_feed plans a republish of an earlier snapshot; apply publishes it. \
                 get_feed and get_feed_history read published snapshots. \
                 An unapproved change is not published.",
            )
    }
}

#[allow(clippy::result_large_err)]
fn proposal_from(entries: &[PlanEntryInput]) -> Result<Proposal, CallToolResult> {
    let mut proposed = Vec::with_capacity(entries.len());
    for entry in entries {
        let kind = gate::parse_kind(&entry.kind)
            .ok_or_else(|| error_result("indicator kind is not acceptable"))?;
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
    Ok(Proposal { entries: proposed })
}

fn view_json(view: &FeedView) -> serde_json::Value {
    json!({
        "version": view.version,
        "digest": view.digest,
        "entries": view.entries.iter().map(row_json).collect::<Vec<_>>(),
    })
}

fn row_json(entry: &SnapshotRow) -> serde_json::Value {
    json!({
        "kind": kind_name(entry.kind),
        "value": entry.value,
        "source": entry.source,
        "confidence": entry.confidence,
        "first_seen": entry.first_seen,
        "last_seen": entry.last_seen,
        "expires_at": entry.expires_at,
        "broad_explicit": entry.broad_explicit,
    })
}

fn kind_name(kind: IndicatorKind) -> &'static str {
    match kind {
        IndicatorKind::Ip => "ip",
        IndicatorKind::Cidr => "cidr",
        IndicatorKind::Domain => "domain",
    }
}

#[allow(clippy::result_large_err)]
fn unix_now() -> Result<i64, CallToolResult> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error_result("clock is not acceptable"))?
        .as_secs();
    i64::try_from(secs).map_err(|_| error_result("clock is not acceptable"))
}

fn gate_text(error: crate::gate::GateError) -> CallToolResult {
    error_result(error.to_string())
}

#[allow(clippy::result_large_err)]
fn misp_query(
    value: Option<String>,
    kind: Option<&str>,
    limit: Option<u32>,
    publisher: &FeedPublisher,
) -> Result<MispQuery, CallToolResult> {
    if let Some(value) = &value
        && (value.is_empty() || value.len() > 256 || value.chars().any(|c| c.is_control()))
    {
        return Err(error_result("MISP request is not acceptable"));
    }
    let max = publisher
        .max_entries()
        .map_err(|_| error_result("feed state is unavailable"))?;
    let limit = match limit {
        None => max,
        Some(0) => return Err(error_result("MISP request is not acceptable")),
        Some(requested) => {
            let requested = usize::try_from(requested)
                .map_err(|_| error_result("MISP request is not acceptable"))?;
            if requested > max {
                return Err(error_result("MISP request is not acceptable"));
            }
            requested
        }
    };
    let kind = match kind {
        None => None,
        Some(name) => Some(
            gate::parse_kind(name)
                .ok_or_else(|| error_result("indicator kind is not acceptable"))?,
        ),
    };
    Ok(MispQuery { value, kind, limit })
}

fn page_json(page: &MispPage) -> serde_json::Value {
    json!({
        "indicators": page.indicators.iter().map(mapped_json).collect::<Vec<_>>(),
        "skipped": page.skipped,
        "truncated": page.truncated,
    })
}

fn mapped_json(entry: &MappedIndicator) -> serde_json::Value {
    json!({
        "kind": kind_name(entry.kind),
        "value": entry.value,
        "source": entry.source,
        "confidence": entry.confidence,
        "first_seen": entry.first_seen,
        "last_seen": entry.last_seen,
    })
}

fn success(value: &impl Serialize) -> Result<CallToolResult, rmcp::ErrorData> {
    match serde_json::to_string_pretty(value) {
        Ok(json) => Ok(CallToolResult::success(vec![ContentBlock::text(json)])),
        Err(_) => error("tool result could not be serialized"),
    }
}

fn error(text: &str) -> Result<CallToolResult, rmcp::ErrorData> {
    Ok(error_result(text))
}

fn error_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text.into())])
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mecfeedmcp_core::{Limits, Policy};
    use mecmcp_auth::ScopeSet;

    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        publisher: Arc<FeedPublisher>,
        handler: FeedHandler,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = Policy::try_new(
            Vec::new(),
            Vec::new(),
            std::iter::empty::<&str>(),
            Limits::default(),
        )
        .expect("policy");
        let publisher = Arc::new(
            FeedPublisher::open(
                &dir.path().join("snapshots"),
                &dir.path().join("changeset-state.json"),
                policy,
                "lab",
                false,
                Duration::from_secs(900),
                mecmcp_audit::signing::generate_keypair().0,
            )
            .expect("open"),
        );
        Fixture {
            handler: FeedHandler::new(Arc::clone(&publisher)),
            publisher,
            _dir: dir,
        }
    }

    fn ctx(name: &str, actor_type: ActorType) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: name.into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(KNOWN_TOOLS.iter().map(|t| (*t).to_string()).collect()),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    fn extensions(caller: Option<CallerCtx<NoGrant>>) -> Extensions {
        let mut extensions = Extensions::new();
        if let Some(caller) = caller {
            let (mut parts, ()) = http::Request::new(()).into_parts();
            parts.extensions.insert(caller);
            extensions.insert(parts);
        }
        extensions
    }

    fn is_error(result: &CallToolResult) -> bool {
        result.is_error == Some(true)
    }

    fn plan_input() -> PlanFeedChangeInput {
        PlanFeedChangeInput {
            entries: vec![PlanEntryInput {
                kind: "ip".to_string(),
                value: "1.0.0.1".to_string(),
                source: "lab".to_string(),
                confidence: 50,
                first_seen: 1_700_000_000,
                last_seen: 1_700_000_000,
                expires_at: None,
                allow_broad_prefix: false,
            }],
        }
    }

    async fn plan_as(f: &Fixture, caller: CallerCtx<NoGrant>) -> (String, String) {
        let result = f
            .handler
            .plan_feed_change(
                Parameters(plan_input()),
                extensions(Some(caller)),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(!is_error(&result), "plan was refused");
        let text = format!("{:?}", result.content);
        let field = |name: &str| {
            let start = text.find(name).expect("field") + name.len();
            let rest = &text[start..];
            let end = rest.find("\\\"").expect("end");
            rest[..end].to_string()
        };
        (field("change_set_id\\\": \\\""), field("digest\\\": \\\""))
    }

    #[tokio::test]
    async fn write_without_a_caller_fails_closed() {
        let f = fixture();
        let result = f
            .handler
            .plan_feed_change(
                Parameters(plan_input()),
                extensions(None),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
        let result = f
            .handler
            .rollback_feed(
                Parameters(RollbackFeedInput {
                    target: 1,
                    expected_latest: 1,
                }),
                extensions(None),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
        assert!(f.publisher.history().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn wildcard_tool_scope_excludes_writes() {
        let f = fixture();
        let mut caller = ctx("alice", ActorType::Human);
        caller.tools = ScopeSet::Wildcard;
        let result = f
            .handler
            .plan_feed_change(
                Parameters(plan_input()),
                extensions(Some(caller)),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
    }

    #[tokio::test]
    async fn device_scope_mismatch_is_refused() {
        let f = fixture();
        let mut caller = ctx("alice", ActorType::Human);
        caller.devices = ScopeSet::Allowlist(vec!["other".to_string()]);
        let result = f
            .handler
            .plan_feed_change(
                Parameters(plan_input()),
                extensions(Some(caller.clone())),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
        let result = f
            .handler
            .get_feed(
                Parameters(GetFeedInput::default()),
                extensions(Some(caller)),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
    }

    #[tokio::test]
    async fn non_human_token_cannot_approve() {
        let f = fixture();
        let (id, digest) = plan_as(&f, ctx("alice", ActorType::Human)).await;
        let input = || {
            Parameters(ChangeSetDigestInput {
                change_set_id: id.clone(),
                digest: digest.clone(),
            })
        };
        let result = f
            .handler
            .approve_feed_change(
                input(),
                extensions(Some(ctx("bot", ActorType::Agent))),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
        let result = f
            .handler
            .apply_feed_change(
                input(),
                extensions(Some(ctx("alice", ActorType::Human))),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
        assert!(f.publisher.latest().expect("lock").is_none());
    }

    #[tokio::test]
    async fn approver_can_read_the_change_set_before_approving() {
        let f = fixture();
        let (id, _) = plan_as(&f, ctx("alice", ActorType::Human)).await;
        let result = f
            .handler
            .get_feed_change(
                Parameters(ChangeSetIdInput { change_set_id: id }),
                extensions(Some(ctx("bob", ActorType::Human))),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(!is_error(&result));
        assert!(format!("{:?}", result.content).contains("1.0.0.1"));
        assert!(f.publisher.latest().expect("lock").is_none());
    }

    #[test]
    fn get_feed_change_is_read_only() {
        assert!(KNOWN_TOOLS.contains(&"get_feed_change"));
        assert!(!WRITE_TOOLS.contains(&"get_feed_change"));
    }

    struct StaticMisp(MispPage);

    #[async_trait::async_trait]
    impl MispSource for StaticMisp {
        async fn search(&self, _query: &MispQuery) -> Result<MispPage, crate::misp::MispError> {
            Ok(self.0.clone())
        }
    }

    fn mapped_ip() -> MappedIndicator {
        MappedIndicator {
            kind: IndicatorKind::Ip,
            value: "1.0.0.1".to_string(),
            source: "misp".to_string(),
            confidence: 50,
            first_seen: 1_700_000_000,
            last_seen: 1_700_000_000,
        }
    }

    fn handler_with_misp(f: &Fixture) -> FeedHandler {
        FeedHandler::with_misp(
            Arc::clone(&f.publisher),
            Some(Arc::new(StaticMisp(MispPage {
                indicators: vec![mapped_ip()],
                skipped: 1,
                truncated: false,
            }))),
        )
    }

    #[tokio::test]
    async fn list_without_misp_fails_closed() {
        let f = fixture();
        let result = f
            .handler
            .list_indicators(
                Parameters(ListIndicatorsInput::default()),
                extensions(Some(ctx("alice", ActorType::Human))),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
        assert!(format!("{:?}", result.content).contains("MISP is not configured"));
    }

    #[tokio::test]
    async fn list_returns_mapped_rows() {
        let f = fixture();
        let handler = handler_with_misp(&f);
        let result = handler
            .list_indicators(
                Parameters(ListIndicatorsInput::default()),
                extensions(Some(ctx("alice", ActorType::Human))),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(!is_error(&result));
        let text = format!("{:?}", result.content);
        assert!(text.contains("1.0.0.1"));
        assert!(text.contains("skipped"));
        assert!(f.publisher.history().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn search_without_a_value_fails_closed() {
        let f = fixture();
        let handler = handler_with_misp(&f);
        let result = handler
            .search_indicators(
                Parameters(SearchIndicatorsInput {
                    query: String::new(),
                    kind: None,
                    limit: None,
                }),
                extensions(Some(ctx("alice", ActorType::Human))),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(is_error(&result));
    }

    #[tokio::test]
    async fn indicator_reads_are_outside_write_tools() {
        assert!(KNOWN_TOOLS.contains(&"list_indicators"));
        assert!(KNOWN_TOOLS.contains(&"search_indicators"));
        assert!(!WRITE_TOOLS.contains(&"list_indicators"));
        assert!(!WRITE_TOOLS.contains(&"search_indicators"));
    }

    #[tokio::test]
    async fn wildcard_tool_scope_can_list() {
        let f = fixture();
        let handler = handler_with_misp(&f);
        let mut caller = ctx("alice", ActorType::Human);
        caller.tools = ScopeSet::Wildcard;
        let result = handler
            .list_indicators(
                Parameters(ListIndicatorsInput::default()),
                extensions(Some(caller)),
                CancellationToken::new(),
            )
            .await
            .expect("call");
        assert!(!is_error(&result));
    }
}
