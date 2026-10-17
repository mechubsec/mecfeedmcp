//! Empty MCP handler. Phase 0 ships no tools; later phases add source
//! readers and the change-set lifecycle on this type.

use rmcp::{
    ServerHandler,
    model::{Implementation, ServerCapabilities, ServerConfig},
};

/// Exact MCP tool registry. Empty until P1.
pub const KNOWN_TOOLS: &[&str] = &[];

/// MCP handler with no registered tools.
#[derive(Clone, Debug, Default)]
pub struct FeedHandler;

impl ServerHandler for FeedHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mecfeedmcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "mecfeedmcp is under construction. No tools are registered yet. \
                 Firewalls must not subscribe to feeds from this version.",
            )
    }
}
