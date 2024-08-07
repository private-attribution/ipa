use std::fmt::Debug;

use clap::{Parser, Subcommand};
use ipa_core::{
    cli::hpke::{decrypt_and_reconstruct, encrypt, DecryptArgs, EncryptArgs},
    error::BoxError,
};

#[derive(Debug, Parser)]
#[clap(name = "hpke", about = "HPKE CLI")]
#[command(about)]
struct Args {
    #[command(subcommand)]
    action: TestHPKECommand,
}

#[derive(Debug, Subcommand)]
enum TestHPKECommand {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    match args.action {
        TestHPKECommand::Encrypt(encrypt_args) => encrypt(&encrypt_args)?,
        TestHPKECommand::Decrypt(decrypt_args) => decrypt_and_reconstruct(decrypt_args).await?,
    }
    Ok(())
}
