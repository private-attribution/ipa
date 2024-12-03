use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

use clap::Args;
use rand::{thread_rng, Rng};
use rand_core::CryptoRng;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, SanType, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

use crate::{error::BoxError, hpke::KeyPair};

#[derive(Debug, Clone, Args)]
#[clap(
    name = "keygen",
    about = "Generate keys used by an MPC helper",
    next_help_heading = "Key Generation Options"
)]
pub struct KeygenArgs {
    /// DNS name to use for the TLS certificate
    #[arg(short, long)]
    pub(crate) name: String,

    /// Writes the generated TLS certificate to the file
    #[arg(long, visible_alias("cert"), visible_alias("tls-certificate"))]
    pub(crate) tls_cert: PathBuf,

    /// Writes the generated TLS private key to the file
    #[arg(long, visible_alias("key"))]
    pub(crate) tls_key: PathBuf,

    /// How long the certificates stay valid before rotation is required.
    #[arg(long, visible_alias("tls-valid-days"), default_value = "91")]
    pub(crate) tls_expire_after: u16,

    /// Optional: Writes the generated report public key to the file
    #[arg(long)]
    pub(crate) mk_public_key: Option<PathBuf>,

    /// Optional: Writes the generated report private key to the file
    #[arg(long)]
    pub(crate) mk_private_key: Option<PathBuf>,
}

fn create_new<P: AsRef<Path>>(path: P) -> io::Result<File> {
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

/// Generate keys necessary for running a helper service.
///
/// # Errors
/// If a problem is encountered during key generation.
///
/// # Panics
/// If something that shouldn't happen goes wrong during key generation.
pub fn keygen_tls<R: Rng + CryptoRng>(args: &KeygenArgs, rng: &mut R) -> Result<(), BoxError> {
    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;

    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = params.not_before + Duration::days(args.tls_expire_after.into());
    params.serial_number = Some(SerialNumber::from(
        rng.gen_range(0..=i64::MAX.try_into().unwrap()),
    ));

    let mut name = DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, args.name.clone());
    params.distinguished_name = name;

    params.subject_alt_names = vec![SanType::DnsName(args.name.clone())];

    let gen = Certificate::from_params(params)?;

    create_new(&args.tls_cert)?
        .write_all(gen.serialize_pem().unwrap().replace('\r', "").as_bytes())?;
    create_new(&args.tls_key)?
        .write_all(gen.serialize_private_key_pem().replace('\r', "").as_bytes())?;

    Ok(())
}

/// Generates public and private key used for encrypting and decrypting match keys.
fn keygen_matchkey<R: Rng + CryptoRng>(args: &KeygenArgs, mut rng: &mut R) -> Result<(), BoxError> {
    let keypair = KeyPair::gen(&mut rng);

    if args.mk_public_key.is_some() && args.mk_private_key.is_some() {
        create_new(args.mk_public_key.as_ref().unwrap())?
            .write_all(hex::encode(keypair.pk_bytes()).as_bytes())?;
        create_new(args.mk_private_key.as_ref().unwrap())?
            .write_all(hex::encode(keypair.sk_bytes()).as_bytes())?;
    }

    Ok(())
}

/// Generate keys necessary for running a helper service.
///
/// # Errors
/// If a problem is encountered during key generation.
///
/// # Panics
/// If something that shouldn't happen goes wrong during key generation.
pub fn keygen(args: &KeygenArgs) -> Result<(), BoxError> {
    let mut rng = thread_rng();
    keygen_tls(args, &mut rng)?;
    keygen_matchkey(args, &mut rng)?;
    Ok(())
}
