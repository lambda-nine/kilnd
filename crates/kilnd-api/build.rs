// B7 milestone 2 recheck 3 HIGH-1: the backstop behind scripts/build.sh's closed compiler
// environment (design section 7.1). Cargo hands a build script the rustc flags it
// compiles this crate with; a `--cfg` among them (a feature cfg no reviewed profile
// selects), an unstable `-Z` flag or a response file fails the build, raw cargo included.
// The same function is in every workspace crate's build script.
fn refuse_compiler_cfg_inputs() {
    println!("cargo:rerun-if-changed=build.rs");
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    for flag in flags.split('\x1f') {
        if flag.starts_with("--cfg") || flag.starts_with("-Z") || flag.starts_with('@') {
            panic!(
                "refused compiler flag {flag:?}: a --cfg, -Z or response-file flag can compile code no reviewed build profile selects; build through scripts/build.sh PROFILE (dependency-gate.json)"
            );
        }
    }
}

// Approved (design 7.1): the one build script that generates code. tonic-prost-build (a build-only
// dependency, B7 milestone 2 LOW-1) runs protoc and writes the gRPC stubs into this
// crate's own build output directory on the build host.
#[allow(clippy::disallowed_methods)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    refuse_compiler_cfg_inputs();
    let proto = "../../proto/kilnd/v1/kilnd.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure().compile_protos(&[proto], &["../../proto"])?;
    Ok(())
}
