// Approved (design 7.1): the one build script. tonic-prost-build (a build-only
// dependency, B7 milestone 2 LOW-1) runs protoc and writes the gRPC stubs into this
// crate's own build output directory on the build host.
#[allow(clippy::disallowed_methods)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/kilnd/v1/kilnd.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure().compile_protos(&[proto], &["../../proto"])?;
    Ok(())
}
