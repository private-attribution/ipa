#[cfg(feature = "enable-serde")]
use crate::error::{Error, Result};
#[cfg(feature = "enable-serde")]
use crate::helpers::Helpers;
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "enable-serde")]
use std::fs;
use std::ops::{Deref, DerefMut};
#[cfg(feature = "enable-serde")]
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum Role {
    Helper1,
    Helper2,
}

/// All of the public information about an aggregation helper.
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PublicHelper {
    role: Role,
}

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Helper {
    #[cfg_attr(feature = "enable-serde", serde(flatten))]
    public: PublicHelper,
}

impl Helper {
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            public: PublicHelper { role },
        }
    }

    /// # Errors
    /// Missing or badly formatted files.
    #[cfg(feature = "enable-serde")]
    pub fn load(dir: &Path, role: Role) -> Result<Self> {
        let s = fs::read_to_string(&Helpers::filename(dir, false))?;
        let v: Self = serde_json::from_str(&s)?;
        if role != v.public.role {
            return Err(Error::InvalidRole);
        }
        Ok(v)
    }

    /// # Errors
    /// Unable to write files.
    #[cfg(feature = "enable-serde")]
    pub fn save(&self, dir: &Path) -> Result<()> {
        let f = Helpers::filename(dir, true);
        fs::write(f, serde_json::to_string_pretty(&self.public)?.as_bytes())?;
        let f = Helpers::filename(dir, false);
        fs::write(f, serde_json::to_string_pretty(&self)?.as_bytes())?;
        Ok(())
    }
}

impl Deref for Helper {
    type Target = PublicHelper;
    fn deref(&self) -> &Self::Target {
        &self.public
    }
}

impl DerefMut for Helper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.public
    }
}
