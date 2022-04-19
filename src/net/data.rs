#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum Command {
    Echo(String),
}

#[cfg(feature = "debug")]
impl Debug for Command {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.write_str("Command::")?;
        match self {
            Self::Echo(_) => f.write_str("Echo"),
        }
    }
}
