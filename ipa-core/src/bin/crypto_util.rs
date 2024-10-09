use std::fmt::Debug;

use clap::{Parser, Subcommand};
use ipa_core::{
    cli::crypto::{DecryptArgs, EncryptArgs},
    error::BoxError,
};

#[derive(Debug, Parser)]
#[clap(name = "crypto-util", about = "Crypto Util CLI")]
#[command(about)]
struct Args {
    #[command(subcommand)]
    action: CryptoUtilCommand,
}

#[derive(Debug, Subcommand)]
enum CryptoUtilCommand {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    match args.action {
        CryptoUtilCommand::Encrypt(encrypt_args) => encrypt_args.encrypt()?,
        CryptoUtilCommand::Decrypt(decrypt_args) => decrypt_args.decrypt_and_reconstruct().await?,
    }
    Ok(())
}
