//! Rust types and gRPC stubs generated from `proto/kilnd/v1/kilnd.proto`.

pub mod v1 {
    #![allow(clippy::pedantic)]
    // ExecStreamResponse's oneof holds ExecFinished (a whole Execution) beside small
    // events; prost generates it unboxed, and one message is built per event.
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("kilnd.v1");
}

/// The `INVALID_ARGUMENT` message of a ListSandboxes or ListCheckpoints request whose
/// `page_size` is above the daemon's `--max-list-page-size` (1 to 1,000). kilndctl
/// recognises exactly this refusal to choose a smaller page.
pub const PAGE_SIZE_EXCEEDS_MAXIMUM: &str = "page_size exceeds server maximum";
