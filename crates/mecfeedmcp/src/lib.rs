//! Governed threat-intel feed MCP server composition.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod gate;
mod handler;
mod http_transport;
mod misp;
mod signals;
mod store;

pub use config::{ConfigError, FeedConfig, MispConfig};
pub use gate::FeedPublisher;
pub use handler::{FeedHandler, KNOWN_TOOLS, WRITE_TOOLS};
pub use http_transport::{build_http_router, serve_http};
pub use misp::{MappedIndicator, MispClient, MispError, MispPage, MispQuery, MispSource};
pub use signals::{SighupHandler, install_early_sighup_handler, install_sighup_handler};
