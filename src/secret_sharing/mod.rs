mod binary;
mod field;
mod malicious_replicated;
mod replicated;
mod shamir;

pub use binary::Binary;
pub use field::{Field, Fp31};
pub use replicated::Replicated;
use serde::{de::DeserializeOwned, Serialize};
pub use shamir::Shamir;
use std::fmt::Debug;

pub trait Share: Copy + Debug + Send + Serialize + DeserializeOwned + 'static {
    const DEFAULT: Self;
}
