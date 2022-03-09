use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::str::FromStr;

/// A string of at most N octets in length.  For use as an argument.
pub struct StringN<const N: usize>(String);
impl<const N: usize> FromStr for StringN<N> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().len() <= N {
            Ok(Self(s.to_owned()))
        } else {
            Err(format!("string was longer than the {} byte limit", N))
        }
    }
}

impl<const N: usize> AsRef<str> for StringN<N> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> Display for StringN<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        f.write_str(&self.0)
    }
}

impl<const N: usize> Debug for StringN<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), FmtError> {
        <Self as Display>::fmt(self, f)
    }
}
