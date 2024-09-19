use std::{io, io::Write};

pub trait Serializer {
    /// Converts self into a CSV-encoded byte string
    /// ## Errors
    /// If this conversion fails due to insufficient capacity in `buf` or other reasons.
    fn to_csv<W: Write>(&self, buf: &mut W) -> io::Result<()>;
}

#[cfg(any(test, feature = "test-fixture"))]
impl Serializer for crate::test_fixture::ipa::TestRawDataRecord {
    fn to_csv<W: Write>(&self, buf: &mut W) -> io::Result<()> {
        // fmt::write is cool because it does not allocate when serializing integers
        write!(buf, "{},", self.timestamp)?;
        write!(buf, "{},", self.user_id)?;
        write!(buf, "{},", u8::from(self.is_trigger_report))?;
        write!(buf, "{},", self.breakdown_key)?;
        write!(buf, "{}", self.trigger_value)?;

        Ok(())
    }
}

#[cfg(any(test, feature = "test-fixture"))]
impl Serializer for crate::test_fixture::hybrid::TestHybridRecord {
    fn to_csv<W: Write>(&self, buf: &mut W) -> io::Result<()> {
        match self {
            crate::test_fixture::hybrid::TestHybridRecord::TestImpression {
                match_key,
                breakdown_key,
            } => {
                write!(buf, "i,{match_key},{breakdown_key}")?;
            }
            crate::test_fixture::hybrid::TestHybridRecord::TestConversion { match_key, value } => {
                write!(buf, "c,{match_key},{value}")?;
            }
        }

        Ok(())
    }
}
