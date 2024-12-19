use std::{
    fmt::Debug,
    io::{self, BufRead},
    sync::Arc,
};

use hyper::header::HeaderName;
use once_cell::sync::Lazy;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;

use crate::{
    config::{OwnedCertificate, OwnedPrivateKey},
    helpers::{HelperIdentity, TransportIdentity},
    sharding::ShardIndex,
};

mod client;
mod error;
mod http_serde;
pub mod query_input;
mod server;
#[cfg(all(test, not(feature = "shuttle")))]
pub mod test;
mod transport;

pub use client::{ClientIdentity, IpaHttpClient};
pub use error::{Error, ShardError};
pub use server::{IpaHttpServer, TracingSpanMaker};
pub use transport::{HttpTransport, MpcHttpTransport, ShardHttpTransport};

const APPLICATION_JSON: &str = "application/json";
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
static HTTP_HELPER_ID_HEADER: HeaderName = HeaderName::from_static("x-unverified-helper-identity");
static HTTP_SHARD_INDEX_HEADER: HeaderName = HeaderName::from_static("x-unverified-shard-index");
static HTTP_QUERY_INPUT_URL_HEADER: HeaderName = HeaderName::from_static("x-query-input-url");

/// This has the same meaning as const defined in h2 crate, but we don't import it directly.
/// According to the [`spec`] it cannot exceed 2^31 - 1.
///
/// Setting up initial window size to this value effectively turns off the flow control mechanism.
/// [`spec`]: <https://datatracker.ietf.org/doc/html/rfc9113#name-the-flow-control-window>
pub(crate) const MAX_HTTP2_WINDOW_SIZE: u32 = (1 << 31) - 1;

pub(crate) const MAX_HTTP2_CONCURRENT_STREAMS: u32 = 5000;

/// Provides access to IPAs Crypto Provider (AWS Libcrypto).
static CRYPTO_PROVIDER: Lazy<Arc<CryptoProvider>> =
    Lazy::new(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));

/// This simple trait is used to make aware on what transport dimnsion one is running. Structs like
/// [`MpcHelperClient<F>`] use it to know whether they are talking to other servers as Shards
/// inside a Helper or as a Helper talking to another Helper in a Ring. This trait can be used to
/// limit the functions exposed by a struct impl, depending on the context that it's being used.
/// Continuing the previous example, the functions a [`MpcHelperClient<F>`] provides are dependent
/// on whether it's communicating with another Shard or another Helper.
///
/// This trait is a safety restriction so that structs or traits only expose an API that's
/// meaningful for their specific context. When used as a generic bound, it also spreads through
/// the types making it harder to be misused or combining incompatible types, e.g. Using a
/// [`ShardIndex`] with a [`Shard`].
pub trait ConnectionFlavor: Debug + Send + Sync + Clone + 'static {
    /// The meaningful identity used in this transport dimension.
    type Identity: TransportIdentity;

    /// The header to be used to identify a HTTP request
    fn identity_header() -> HeaderName;
}

/// Shard-to-shard communication marker.
/// This marker is used to restrict communication inside a single Helper, with other shards.
#[derive(Debug, Copy, Clone)]
pub struct Shard;

/// Helper-to-helper communication marker.
/// This marker is used to restrict communication between Helpers. This communication usually has
/// more restrictions. 3 Hosts with the same sharding index are conencted in a Ring.
#[derive(Debug, Copy, Clone)]
pub struct Helper;

impl ConnectionFlavor for Shard {
    type Identity = ShardIndex;

    fn identity_header() -> HeaderName {
        HTTP_SHARD_INDEX_HEADER.clone()
    }
}
impl ConnectionFlavor for Helper {
    type Identity = HelperIdentity;

    fn identity_header() -> HeaderName {
        HTTP_HELPER_ID_HEADER.clone()
    }
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

    use super::test::get_test_certificate_and_key;
    use crate::sharding::ShardedHelperIdentity;

    const NOTHING: &[u8] = b" ";
    const GARBAGE: &[u8] = b"ksjdhfskjdfhsdf";

    #[test]
    fn parse_cert_pk_happy_path() {
        let (mut c, mut pk) = get_test_certificate_and_key(ShardedHelperIdentity::ONE_FIRST);
        super::parse_certificate_and_private_key_bytes(&mut c, &mut pk).unwrap();
    }

    #[test]
    #[should_panic(expected = "No certificates found")]
    fn parse_cert_pk_no_cert() {
        let mut c = NOTHING;
        let (_, mut pk) = get_test_certificate_and_key(ShardedHelperIdentity::ONE_FIRST);
        let r = super::parse_certificate_and_private_key_bytes(&mut c, &mut pk);
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::Other);
        r.unwrap();
    }

    #[test]
    #[should_panic(expected = "No private key")]
    fn parse_cert_pk_no_pk() {
        let (mut c, _) = get_test_certificate_and_key(ShardedHelperIdentity::ONE_FIRST);
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
