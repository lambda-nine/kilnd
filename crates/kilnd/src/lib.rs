//! kilnd: a per-node control daemon for sandboxes. It owns sandbox state in
//! SQLite, drives an isolation backend through the [`runtime::Runtime`]
//! trait (kiln first), and serves the `kilnd.v1` gRPC API on a Unix socket.

pub mod admission;
pub mod attachment_check;
pub mod manager;
pub mod model;
pub mod process;
pub mod runtime;
pub mod server;
pub mod service;
pub mod store;
/// Typed system-call and ioctl wrappers: the only non-gate users of `libc::syscall`
/// and `libc::ioctl` (design section 7.1).
pub mod sys;
mod validation;

mod lock;

pub mod retention;

pub mod helper;

/// Phase 1b frozen byte and execution-spec contract; production launch is disabled.
pub mod firecracker;
