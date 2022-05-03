// use std::fs::OpenOptions;
// use std::io::{Read, Seek};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "src/proto";
    tonic_build::configure()
        .out_dir(out_dir)
        .type_attribute(".", "#[allow(clippy::similar_names)]")
        .compile(&["proto/pipe.proto"], &["proto"])?;
    Ok(())
    // let mut file = OpenOptions::new().read(true).append(true).open(out_dir)?;
    // let mut compiled = String::new();
    // file.read_to_string(&mut compiled)?;
    // String::new()
}
