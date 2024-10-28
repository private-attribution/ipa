use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct HybridQueryParams {
    #[cfg_attr(feature = "clap", arg(long, default_value = "8"))]
    pub per_user_credit_cap: u32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "5"))]
    pub max_breakdown_key: u32,
    #[cfg_attr(feature = "clap", arg(short = 'd', long, default_value = "1"))]
    pub with_dp: u32,
    #[cfg_attr(feature = "clap", arg(short = 'e', long, default_value = "5.0"))]
    pub epsilon: f64,
    #[cfg_attr(feature = "clap", arg(long))]
    #[serde(default)]
    pub plaintext_match_keys: bool,
}

#[cfg(test)]
impl Eq for HybridQueryParams {}

impl Default for HybridQueryParams {
    fn default() -> Self {
        Self {
            per_user_credit_cap: 8,
            max_breakdown_key: 20,
            with_dp: 1,
            epsilon: 0.10,
            plaintext_match_keys: false,
        }
    }
}
