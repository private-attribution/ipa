use std::{io, io::Write};

pub trait Serializer {
    /// Converts self into a CSV-encoded byte string
    /// ## Errors
    /// If this conversion fails due to insufficient capacity in `buf` or other reasons.
    fn to_csv<W: Write>(&self, buf: &mut W) -> io::Result<()>;
}

#[cfg(any(test, feature = "test-fixture"))]
impl Serializer for crate::test_fixture::hybrid::TestHybridRecord {
    fn to_csv<W: Write>(&self, buf: &mut W) -> io::Result<()> {
        match self {
            crate::test_fixture::hybrid::TestHybridRecord::TestImpression {
                match_key,
                breakdown_key,
                key_id,
            } => {
                write!(buf, "i,{match_key},{breakdown_key},{key_id}")?;
            }
            crate::test_fixture::hybrid::TestHybridRecord::TestConversion {
                match_key,
                value,
                key_id,
                conversion_site_domain,
                timestamp,
                epsilon,
                sensitivity,
            } => {
                write!(buf, "c,{match_key},{value},{key_id},{conversion_site_domain},{timestamp},{epsilon},{sensitivity}")?;
            }
        }

        Ok(())
    }
}
