//! kilnd: a per-node control daemon for sandboxes. It owns sandbox state in
//! SQLite, drives an isolation backend through the [`runtime::Runtime`]
//! trait (kiln first), and serves the `kilnd.v1` gRPC API on a Unix socket.

pub mod admission;
pub mod manager;
pub mod model;
pub mod process;
pub mod runtime;
pub mod server;
pub mod service;
pub mod store;
mod validation;

mod lock;

pub mod retention;
