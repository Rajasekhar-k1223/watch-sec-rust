fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/telemetry.proto");
    
    tonic_build::configure()
        .build_server(false)
        .compile(&["proto/telemetry.proto"], &["proto"])?;
        
    Ok(())
}
