//! KDX server domain logic: connection state machine, auth, chat rooms,
//! virtual file tree, transfers, and the tracker service. Modules are generic
//! over `AsyncRead + AsyncWrite` where they touch a stream, so tests can use
//! in-memory duplex pipes instead of real sockets.

pub mod auth;
pub mod chat;
pub mod connection;
pub mod files;
pub mod history;
pub mod news;
pub mod presence;
pub mod settings;
pub mod tracker;
pub mod transfer;

pub use connection::{Connection, ConnectionError, ServerCtx};
pub use presence::Presence;
