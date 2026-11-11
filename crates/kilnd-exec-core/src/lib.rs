//! kilnd's direct-kiln core: the fixed-tool process runner, the persistent-exec owner
//! and its strict status codec, output capture, request validation and the direct
//! execution path through kiln's cleanup barrier.
//!
//! Phase 1b B5 moved these from the `kilnd` crate, unchanged, so the guest broker
//! (`kilnd-guest-broker`) reuses the reviewed code instead of reimplementing kiln's
//! machine protocol. The module paths mirror kilnd's (`process`, `runtime::kiln_process`
//! and so on), and kilnd re-exports every item, so its interfaces are unchanged. This
//! crate has no gRPC, SQLite or helper server; see the B5 move audit in
//! `docs/design/phase1b-firecracker.md`.

/// Exec cwd and env (API additions design 4): validation, the merge and kiln's frame.
pub mod exec_options;
/// The live output tap (API additions design 5.1): an observer the capture readers offer
/// bytes to after counting them, which can never backpressure them.
pub mod live;
pub mod model;
pub mod process;
pub mod runtime;
/// Typed system-call wrappers for the child setup: the only non-gate users of
/// `libc::syscall` and `libc::prctl` in this crate (design section 7.1).
pub mod sys;
pub mod validation;
