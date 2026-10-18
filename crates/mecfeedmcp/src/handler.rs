//! MCP tools for planning, approving, and publishing feed snapshots.
//!
//! The caller principal comes from the authenticated token. Tool arguments
//! do not name an approver. A write with no caller is refused.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mecfeedmcp_core::{IndicatorKind, Proposal, ProposedEntry};
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

macro_rules! admit {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(denial) => return Ok(denial),
        }
    };
}

/// Tools this server registers.
pub const KNOWN_TOOLS: &[&str] = &[
    "get_feed",
    "get_feed_history",
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
    tool_router: ToolRouter<Self>,
}

impl FeedHandler {
    /// Register the feed tools on `publisher`.
    #[must_use]
    pub fn new(publisher: Arc<FeedPublisher>) -> Self {
        Self {
            publisher,
            tool_router: Self::tool_router(),
        }
    }

    fn caller(extensions: &Extensions) -> Option<CallerCtx<NoGrant>> {
        extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<CallerCtx<NoGrant>>())
            .cloned()
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

/// Arguments for [`FeedHandler::rollback_feed`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackFeedInput {
    /// Snapshot version to republish.
    pub target: u64,
    /// Latest version the caller saw.
    pub expected_latest: u64,
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
        admit!(self.authorize(&extensions, "get_feed", false));
        let view = match input.version {
            Some(number) => admit!(self.publisher.history().map_err(gate_text))
                .into_iter()
                .find(|view| view.version == number),
            None => admit!(self.publisher.latest().map_err(gate_text)),
        };
        let Some(view) = view else {
            return error("snapshot was not found");
        };
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
        admit!(self.authorize(&extensions, "get_feed_history", false));
        let views = admit!(self.publisher.history().map_err(gate_text));
        success(&json!({
            "snapshots": views.iter().map(view_json).collect::<Vec<_>>(),
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
        let caller = admit!(self.require_writer(&extensions, "plan_feed_change"));
        let now = admit!(unix_now());
        let proposal = admit!(proposal_from(&input.entries));
        let receipt = admit!(
            self.publisher
                .plan(&caller.token_name, proposal, now)
                .await
                .map_err(gate_text)
        );
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
        description = "Approve one stored feed digest. Production requires a different human principal. Lab mode records a waiver by the owner"
    )]
    async fn approve_feed_change(
        &self,
        Parameters(input): Parameters<ChangeSetDigestInput>,
        extensions: Extensions,
        _cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = admit!(self.require_writer(&extensions, "approve_feed_change"));
        let result = if self.publisher.lab_mode() {
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
        admit!(result.map_err(gate_text));
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
        let caller = admit!(self.require_writer(&extensions, "apply_feed_change"));
        let now = admit!(unix_now());
        let published = admit!(
            self.publisher
                .apply(&caller.token_name, &input.change_set_id, &input.digest, now)
                .await
                .map_err(gate_text)
        );
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
        let caller = admit!(self.require_writer(&extensions, "rollback_feed"));
        let now = admit!(unix_now());
        let receipt = admit!(
            self.publisher
                .stage_rollback(&caller.token_name, input.target, input.expected_latest, now,)
                .await
                .map_err(gate_text)
        );
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
                 plan_feed_change admits a proposal and stores a digest. \
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
        "entries": view.entries.iter().map(|entry| json!({
            "kind": kind_name(entry.kind),
            "value": entry.value,
            "source": entry.source,
            "confidence": entry.confidence,
            "first_seen": entry.first_seen,
            "last_seen": entry.last_seen,
            "expires_at": entry.expires_at,
            "broad_explicit": entry.broad_explicit,
        })).collect::<Vec<_>>(),
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
