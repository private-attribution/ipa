pub mod replicated;

mod decomposed;
mod into_shares;
mod scheme;

pub use decomposed::BitDecomposed;
pub use into_shares::IntoShares;
pub use scheme::{Bitwise, Linear, SecretSharing};

use crate::ff::{ArithmeticOps, Serializable};
use generic_array::ArrayLength;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing};
use std::fmt::Debug;

// Trait for primitive integer types used to represent the underlying type for shared values
pub trait Block: Sized + Copy + Debug {
    /// Size of a block in bytes big enough to hold the shared value. `Size * 8 >= VALID_BIT_LENGTH`.
    type Size: ArrayLength<u8>;
}

pub trait SharedValue:
    Clone + Copy + PartialEq + Debug + Send + Sync + Sized + ArithmeticOps + Serializable + 'static
{
    type Storage: Block;

    const BITS: u32;

    const ZERO: Self;
}

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
impl<V> IntoShares<AdditiveShare<V>> for V
where
    V: SharedValue,
    Standard: Distribution<V>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AdditiveShare<V>; 3] {
        let x1 = rng.gen::<V>();
        let x2 = rng.gen::<V>();
        let x3 = self - (x1 + x2);

        [
            AdditiveShare::new(x1, x2),
            AdditiveShare::new(x2, x3),
            AdditiveShare::new(x3, x1),
        ]
    }
}
