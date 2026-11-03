//! Runs one host program with an argument vector, bounded output, a timeout
//! and cancellation. Phase 1b B5 moved the runner to the direct-kiln core crate
//! (`kilnd_exec_core::process`), which the guest broker shares; this module re-exports
//! it unchanged.

#[cfg(target_os = "linux")]
pub use kilnd_exec_core::process::require_firecracker_launch_capabilities_dropped;
pub use kilnd_exec_core::process::{
    CaptureCompletion, Finish, KilnArgs, KilnBinary, Outcome, Request, SAFE_PATH, SpawnGuard, Tool,
    run, spawn_guard,
};
