/// this is experimental
/// do not use (yet)
///
mod de;
mod ser;

pub use de::{from_str, PathDeserializer};
pub use ser::{to_string, PathSerializer};

use std::fmt::Display;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("type not implemented")]
    NotImplemented,
    #[error("eof")]
    Eof,
    #[error("trailing characters")]
    TrailingCharacters,
    #[error("expected {0}")]
    Expected(&'static str),
    #[error("bad syntax")]
    Syntax,
}

impl serde::ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Error::Message(msg.to_string())
    }
}
