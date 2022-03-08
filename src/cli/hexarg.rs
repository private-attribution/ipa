use hex::{self, FromHexError};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::str::FromStr;

#[derive(Debug)]
pub enum HexArgError<const N: usize> {
    Hex(FromHexError),
    Length(usize),
}
impl<const N: usize> From<FromHexError> for HexArgError<N> {
    fn from(e: FromHexError) -> Self {
        Self::Hex(e)
    }
}
impl<const N: usize> ToString for HexArgError<N> {
    fn to_string(&self) -> String {
        match self {
            Self::Hex(e) => e.to_string(),
            Self::Length(l) => format!("hex value is {} bytes, {} is needed", l, N),
        }
    }
}

pub struct HexArg<const N: usize>([u8; N]);
impl<const N: usize> FromStr for HexArg<N> {
    type Err = HexArgError<N>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = hex::decode(s)?;
        let v = <[u8; N]>::try_from(b).map_err(|v| HexArgError::Length(v.len()))?;
        Ok(Self(v))
    }
}

impl<const N: usize> AsRef<[u8; N]> for HexArg<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Display for HexArg<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        f.write_str(&hex::encode(self.0))
    }
}

impl<const N: usize> Debug for HexArg<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), FmtError> {
        <Self as Display>::fmt(self, f)
    }
}
