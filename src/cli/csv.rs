use std::{io, io::Write};

pub trait CsvSerializer {
    fn to_csv<W: Write>(&self, buf: &mut W) -> io::Result<()>;
}

#[cfg(any(test, feature = "test-fixture"))]
impl CsvSerializer for crate::test_fixture::ipa::TestRawDataRecord {
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
