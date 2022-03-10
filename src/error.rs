#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    Internal,
    InvalidId,
    InvalidRole,
    NotEnoughHelpers,
    NotFound,
    RedisError(redis::RedisError),
    TooManyHelpers,

    #[cfg(feature = "cli")]
    Hex(hex::FromHexError),
    Io(std::io::Error),
    #[cfg(feature = "enable-serde")]
    Serde(serde_json::Error),
}

macro_rules! forward_errors {
    {$($(#[$a:meta])* $t:path => $v:ident),* $(,)?} => {
        $(
            $(#[$a])*
            impl From<$t> for Error {
                fn from(e: $t) -> Self {
                    Self::$v(e)
                }
            }
        )*

        impl std::error::Error for Error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $( $(#[$a])* Self::$v(e) => Some(e), )*
                    _ => None,
                }
            }
        }
    };
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

forward_errors! {
    #[cfg(feature = "cli")]
    hex::FromHexError => Hex,
    std::io::Error => Io,
    #[cfg(feature = "enable-serde")]
    serde_json::Error => Serde,
    redis::RedisError => RedisError,
}

pub type Res<T> = Result<T, Error>;
