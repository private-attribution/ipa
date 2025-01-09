use std::fmt::Debug;

use clap::{Parser, Subcommand};
use ipa_core::{
    cli::{
        crypto::{HybridDecryptArgs, HybridEncryptArgs},
        Verbosity,
    },
    error::BoxError,
};

#[derive(Debug, Parser)]
#[clap(name = "crypto-util", about = "Crypto Util CLI")]
#[command(about)]
struct Args {
    // Configure logging.
    #[clap(flatten)]
    logging: Verbosity,

    #[command(subcommand)]
    action: CryptoUtilCommand,
}

#[derive(Debug, Subcommand)]
enum CryptoUtilCommand {
    HybridEncrypt(HybridEncryptArgs),
    HybridDecrypt(HybridDecryptArgs),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();
    match args.action {
        CryptoUtilCommand::HybridEncrypt(hybrid_encrypt_args) => hybrid_encrypt_args.encrypt()?,
        CryptoUtilCommand::HybridDecrypt(hybrid_decrypt_args) => {
            hybrid_decrypt_args.decrypt_and_reconstruct().await?
        }
    }
    Ok(())
}
