use std::ffi::OsStr;
use std::fs::{read_dir, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "src/proto";
    let prepend_str = String::from(
        "\
#![allow(clippy::pedantic)]

",
    );
    tonic_build::configure()
        .out_dir(out_dir)
        .compile(&["proto/pipe.proto"], &["proto"])?;
    visit_files(
        Path::new(&out_dir),
        &(|file| prepend(file, prepend_str.clone())),
    )?;
    Ok(())
}

fn visit_files(
    dir_or_file: &Path,
    cb: &dyn Fn(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if dir_or_file.is_dir() {
        read_dir(dir_or_file)?
            .try_for_each(|inner_dir_or_file| visit_files(&inner_dir_or_file?.path(), cb))
    } else if dir_or_file.file_name().unwrap() == OsStr::new("rustfmt.toml") {
        Ok(())
    } else {
        cb(dir_or_file)
    }
}

fn prepend(path: &Path, mut str: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    file.read_to_string(&mut str)?;
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(str.as_bytes())?;
    Ok(())
}
