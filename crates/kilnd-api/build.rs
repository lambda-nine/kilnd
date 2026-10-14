fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/kilnd/v1/kilnd.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure().compile_protos(&[proto], &["../../proto"])?;
    Ok(())
}
