//! Governed threat-intel feed MCP server composition.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod gate;
mod handler;
mod http_transport;
mod signals;
mod store;

pub use gate::FeedPublisher;
pub use handler::{FeedHandler, KNOWN_TOOLS, WRITE_TOOLS};
pub use http_transport::{build_http_router, serve_http};
pub use signals::{SighupHandler, install_early_sighup_handler, install_sighup_handler};
