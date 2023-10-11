use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct QueryConfig {
    pub bk_size: u8, // breakdown key size bits
    pub tv_size: u8, // trigger value size bits
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            bk_size: 40,
            tv_size: 40,
        }
    }
}
