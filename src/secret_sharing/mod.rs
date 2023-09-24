pub mod replicated;

mod decomposed;
mod into_shares;
mod scheme;

use std::fmt::Debug;

pub use decomposed::BitDecomposed;
use generic_array::ArrayLength;
pub use into_shares::IntoShares;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing};
pub use scheme::{Bitwise, Linear, SecretSharing};

use crate::ff::{ArithmeticOps, Serializable};

// Trait for primitive integer types used to represent the underlying type for shared values
pub trait Block: Sized + Copy + Debug {
    /// Size of a block in bytes big enough to hold the shared value. `Size * 8 >= VALID_BIT_LENGTH`.
    type Size: ArrayLength<u8>;
}

pub trait SharedValue:
// TODO: add reference operations
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


#[cfg(all(test, unit_test))]
mod tests {
    use std::ops::Add;
    use crate::ff::{Field, Fp31};
    use crate::secret_sharing::{Linear, SharedValue};
    use crate::secret_sharing::replicated::semi_honest::AdditiveShare;
    use crate::secret_sharing::scheme::RefLocalArithmeticOps;

    #[test]
    fn arithmetic() {
        let a = AdditiveShare::<Fp31>::ZERO;
        let b = AdditiveShare::<Fp31>::ZERO;

        assert_eq!(AdditiveShare::ZERO, &a + &b);
        assert_eq!(AdditiveShare::ZERO, a.clone() + &b);
        assert_eq!(AdditiveShare::ZERO, &a + b.clone());
        assert_eq!(AdditiveShare::ZERO, a + b);
    }

    #[test]
    fn trait_bounds() {
        fn sum_owned<S: Linear<Fp31>>(a: S, b: S) -> S {
            a + b
        }

        fn sum_ref_ref<S>(a: &S, b: &S) -> S where S: Linear<Fp31>, for <'a> &'a S: RefLocalArithmeticOps<'a, S> {
            a + b
        }

        fn sum_owned_ref<S: Linear<Fp31>>(a: S, b: &S) -> S {
            a + b
        }

        // fn sum_ref_owned<S, V>(a: &S, b: S) -> S where S: Linear<V>, V: SharedValue, for <'a> &'a S: RefLocalArithmeticOps<S> {
        //     a + b
        // }

        assert_eq!(AdditiveShare::ZERO, sum_owned(AdditiveShare::ZERO, AdditiveShare::ZERO));
        assert_eq!(AdditiveShare::<Fp31>::ZERO, sum_ref_ref(&AdditiveShare::<Fp31>::ZERO, &AdditiveShare::ZERO));
        assert_eq!(AdditiveShare::ZERO, sum_owned_ref(AdditiveShare::ZERO, &AdditiveShare::ZERO));
        // assert_eq!(0, sum_ref_owned(&0_i32, 1));
        // assert_eq!(AdditiveShare::<Fp31>::ZERO, sum_ref_owned::<AdditiveShare<Fp31>, _>(&AdditiveShare::ZERO, AdditiveShare::ZERO))
        // assert_eq!(AdditiveShare::ZERO, sum_ref_owned::<AdditiveShare<Fp31>>(&AdditiveShare::ZERO, AdditiveShare::ZERO));
    }
}
