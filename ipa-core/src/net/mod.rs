use std::{
    io::{self, BufRead},
    sync::{Arc, Once},
};

use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;

use crate::config::{OwnedCertificate, OwnedPrivateKey};

mod client;
mod error;
mod http_serde;
mod server;
#[cfg(all(test, not(feature = "shuttle")))]
pub mod test;
mod transport;

pub use client::{ClientIdentity, MpcHelperClient};
pub use error::Error;
pub use server::{MpcHelperServer, TracingSpanMaker};
pub use transport::{HttpShardTransport, HttpTransport};

static CRYPTO_INIT: Once = Once::new();

/// Provides access to IPAs Crypto Provider (AWS Libcrypto).
///
/// # Panics
/// If there are issues starting the default crypto provider
pub fn get_crypto_provider() -> &'static Arc<CryptoProvider> {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    CryptoProvider::get_default().expect("Default Crypto provider should be initialized")
}

/// Reads certificates and a private key from the corresponding readers
///
/// # Errors
/// If no private key or certificates are found and if there are any issues with
/// their format.
pub fn parse_certificate_and_private_key_bytes(
    cert_read: &mut dyn BufRead,
    private_key_read: &mut dyn BufRead,
) -> Result<(Vec<OwnedCertificate>, OwnedPrivateKey), io::Error> {
    let certs = rustls_pemfile::certs(cert_read)
        .map(|r| r.map(CertificateDer::into_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::other("No certificates found"));
    }
    let pk = rustls_pemfile::private_key(private_key_read)?
        .ok_or_else(|| io::Error::other("No private key"))?;
    Ok((certs, pk))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::io::ErrorKind;

    use crate::net::test;

    const NOTHING: &[u8] = b" ";
    const GARBAGE: &[u8] = b"ksjdhfskjdfhsdf";

    #[test]
    fn parse_cert_pk_happy_path() {
        let mut c = test::TEST_CERTS[0];
        let mut pk = test::TEST_KEYS[0];
        super::parse_certificate_and_private_key_bytes(&mut c, &mut pk).unwrap();
    }

    #[test]
    #[should_panic(expected = "No certificates found")]
    fn parse_cert_pk_no_cert() {
        let mut c = NOTHING;
        let mut pk = test::TEST_KEYS[0];
        let r = super::parse_certificate_and_private_key_bytes(&mut c, &mut pk);
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::Other);
        r.unwrap();
    }

    #[test]
    #[should_panic(expected = "No private key")]
    fn parse_cert_pk_no_pk() {
        let mut c = test::TEST_CERTS[0];
        let mut pk = NOTHING;
        let r = super::parse_certificate_and_private_key_bytes(&mut c, &mut pk);
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::Other);
        r.unwrap();
    }

    #[test]
    #[should_panic(expected = "No certificates found")]
    fn parse_cert_pk_invalid() {
        let mut c = GARBAGE;
        let mut pk = GARBAGE;
        let r = super::parse_certificate_and_private_key_bytes(&mut c, &mut pk);
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::Other);
        r.unwrap();
    }
}
