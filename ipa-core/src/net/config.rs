use std::{
    fmt::Debug,
    io::{self, BufRead},
    sync::Arc,
};

use config::{Config, File, FileFormat};
use hyper::{header::HeaderName, Uri};
use once_cell::sync::Lazy;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;
use ::serde::Deserialize;

use crate::{
    config::{ClientConfig, OwnedCertificate, OwnedPrivateKey, PeerConfig}, helpers::{HelperIdentity, TransportIdentity}, serde, sharding::ShardIndex
};



#[cfg(all(test, unit_test))]
mod tests {
    


}
