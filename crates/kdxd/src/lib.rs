//! kdxd library surface: config loading and the TLS accept loop, exposed so
//! integration tests can run a real server in-process on an ephemeral port.

pub mod cli;
pub mod config;
pub mod listener;
pub mod sys;

pub use config::Config;
pub use listener::{serve, Server};
