use std::{
    io,
    io::{BufRead, BufReader, Cursor},
};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

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

/// Reads certificates and a private key from the corresponding bytes
///
/// # Errors
/// If no private key or certificates are found and if there are any issues with
/// their format.
pub fn parse_certificate_and_private_key_bytes(
    cert_bytes: &[u8],
    private_key_bytes: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), io::Error> {
    let mut certs_reader = BufReader::new(Cursor::new(cert_bytes));
    let mut private_key_reader = BufReader::new(Cursor::new(private_key_bytes));
    parse_certificate_and_private_key(&mut certs_reader, &mut private_key_reader)
}

/// Reads certificates and a private key from the corresponding buffered inputs
///
/// # Errors
/// If no private key or certificates are found and if there are any issues with
/// their format.
pub fn parse_certificate_and_private_key(
    cert_reader: &mut dyn BufRead,
    private_key_reader: &mut dyn BufRead,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), io::Error> {
    let cert_chain: Vec<_> = rustls_pemfile::certs(cert_reader)
        .flatten()
        .map(CertificateDer::into_owned)
        .collect();
    let pk = rustls_pemfile::private_key(private_key_reader)?.ok_or_else(||
      io::Error::other("No private key")
    )?;
    if cert_chain.is_empty() {
        return Err(io::Error::other("No certificates found"));
    }
    Ok((cert_chain, pk))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::io::ErrorKind;

    use crate::net::test;

    #[test]
    fn parse_cert_pk_happy_path() {
        super::parse_certificate_and_private_key_bytes(test::TEST_CERTS[0], test::TEST_KEYS[0])
            .unwrap();
    }

    #[test]
    fn parse_cert_pk_no_cert() {
        let r = super::parse_certificate_and_private_key_bytes(b" ", test::TEST_KEYS[0]);
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Other);
    }

    #[test]
    fn parse_cert_pk_no_pk() {
        let r = super::parse_certificate_and_private_key_bytes(test::TEST_CERTS[0], b" ");
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Other);
    }

    #[test]
    fn parse_cert_pk_invalid() {
        let r =
            super::parse_certificate_and_private_key_bytes(b"ksjdhfskjdfhsdf", test::TEST_KEYS[0]);
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Other);
    }
}
