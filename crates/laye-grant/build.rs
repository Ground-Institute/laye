// The contract is proto/laye/v1/laye.proto, and the types are built from it:
// there is no second writing of it in Rust to drift from.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/laye/v1/laye.proto");
    prost_build::compile_protos(&["../../proto/laye/v1/laye.proto"], &["../../proto"])?;
    Ok(())
}
