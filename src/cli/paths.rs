use std::path::Path;

/// Naming conventions for files that store public/private HPKE and TLS keys.
pub trait PathExt: ToOwned {
    fn helper_tls_cert<I: Into<u8>>(&self, id: I) -> Self::Owned;
    fn helper_tls_key<I: Into<u8>>(&self, id: I) -> Self::Owned;
    fn helper_mk_public_key<I: Into<u8>>(&self, id: I) -> Self::Owned;
    fn helper_mk_private_key<I: Into<u8>>(&self, id: I) -> Self::Owned;
}

impl PathExt for Path {
    fn helper_tls_cert<I: Into<u8>>(&self, id: I) -> Self::Owned {
        let id = id.into();
        self.join(format!("h{id}.pem"))
    }

    fn helper_tls_key<I: Into<u8>>(&self, id: I) -> Self::Owned {
        let id = id.into();
        self.join(format!("h{id}.key"))
    }

    fn helper_mk_public_key<I: Into<u8>>(&self, id: I) -> Self::Owned {
        let id = id.into();
        self.join(format!("h{id}_mk.pub"))
    }

    fn helper_mk_private_key<I: Into<u8>>(&self, id: I) -> Self::Owned {
        let id = id.into();
        self.join(format!("h{id}_mk.key"))
    }
}
