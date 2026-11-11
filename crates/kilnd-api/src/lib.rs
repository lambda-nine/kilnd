//! Rust types and gRPC stubs generated from `proto/kilnd/v1/kilnd.proto`.

pub mod v1 {
    #![allow(clippy::pedantic)]
    // ExecStreamResponse's oneof holds ExecFinished (a whole Execution) beside small
    // events; prost generates it unboxed, and one message is built per event.
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("kilnd.v1");
}
