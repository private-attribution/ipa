use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use crate::{
    error::LengthError,
    ff::Field,
    protocol::prss::FromRandom,
    secret_sharing::{Sendable, SharedValue},
};

// Note that we can either make `trait Vectorizable<N>: SharedValue`, or we can make `trait
// SharedValue: Vectorizable<1>`, but doing both creates a cycle. (Similarly for
// `FieldVectorizable` / `Field`.)
//
// Although it is somewhat unnatural, we choose to do the latter, because it allows existing
// high-level protocols unaware of vectorization to call vectorized versions of core protocols (with
// width of 1) without updating all of the trait bounds. This does mean that the trait definitions
// do not prevent implementing `Vectorizable` for something that is not a `SharedValue`, but please
// don't do that.

/// Trait for `SharedValue`s supporting operations on `N`-wide vectors.
pub trait Vectorizable<const N: usize>: Sized {
    type Array: SharedValueArray<Self>;
}

/// Trait for `Field`s supporting operations on `N`-wide vectors.
///
/// We would like `F` to be `FieldVectorizable` if it satisfies all of the following:
///  1. `F: Field`.
///  2. `<F as Vectorizable<N>>::Array: FieldArray<Self>`. Rust does not support expressing a
///     constraint on a super-trait's associated type directly. Instead, this effect is achieved
///     by constraining the `ArrayAlias` associated type and then constraining that
///     `Vectorizable::Array == FieldVectorizable::ArrayAlias` where necessary (e.g. in the
///     definition and blanket impl of the `FieldSimd` trait. We call it `ArrayAlias` instead of
///     `Array` so that references to the `Array` associated type do not require qualification
///     with a trait name.
///  3. `F: Vectorizable<N>`. This is implied by the previous two, because `FieldArray`
///     is a sub-trait of `SharedValueArray`. (See the `FieldSimd` documentation for another
///     important consequence of this sub-trait relationship.)
pub trait FieldVectorizable<const N: usize>: SharedValue + Sized {
    type ArrayAlias: FieldArray<Self>;
}

// Convenience alias to express a supported vectorization when writing protocols.
//
// Typically appears like this: `F: Field + FieldSimd<N>`.
//
// We could define a `SharedValueSimd` trait that is the analog of this for `SharedValue`s, but
// there are not currently any protocols that need it.
//
// Because we have constrained the associated types Vectorizable::Array and
// FieldVectorizable::ArrayAlias to be equal, the type they refer to must satisfy the union of all
// trait bounds applicable to either. However, in some cases the compiler has trouble proving
// properties related to this. (See rust issues [41118] and [60471].) A typical workaround for
// problems of this sort is to redundantly list a trait bound on both associated types, but for us
// that is not necessary in most cases because `FieldArray` is a sub-trait of `SharedValueArray`.
//
// Another consequence of this limitation of the compiler is that if you write the bound `F: Field +
// FieldSimd<N> + Vectorizable<N, Array = S>`, you will get the error ``type annotations needed:
// cannot satisfy `<F as secret_sharing::Vectorizable<N>>::Array == <F as
// secret_sharing::FieldVectorizable<N>>::ArrayAlias```. The compiler is not smart enough to
// coalesce the constraints and see that `S`, `<F as Vectorizable>::Array`, and `<F as
// FieldVectorizable>::ArrayAlias` must all to refer to the same type.
//
// [41118](https://github.com/rust-lang/rust/issues/41118)
// [60471](https://github.com/rust-lang/rust/issues/60471)
pub trait FieldSimd<const N: usize>:
    Field + Vectorizable<N, Array = <Self as FieldVectorizable<N>>::ArrayAlias> + FieldVectorizable<N>
{
}

// Portions of the implementation treat non-vectorized operations as a vector with `N = 1`. This
// blanket impl (and the fact that `F: Field` is the only trait bound) is important in allowing code
// that writes `F: Field` to continue working without modification.
impl<F: Field> FieldSimd<1> for F {}

pub trait SharedValueArray<V>:
    Clone
    + Eq
    + Debug
    + Send
    + Sync
    + Sized
    + Sendable
    + TryFrom<Vec<V>, Error = LengthError>
    + FromIterator<V>
    + IntoIterator<Item = V>
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Neg<Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
{
    const ZERO_ARRAY: Self;

    fn from_fn<F: FnMut(usize) -> V>(f: F) -> Self;
}

// Some `SharedValue` types (and thus their arrays) implement `FromRandom`, but `RP25519` does not.
// We overload this distinction on `FieldArray` instead of creating a separate `ArrayFromRandom` trait,
// to avoid making the `Vectorizable` / `FieldVectorizable` situation that much more complicated.
pub trait FieldArray<F: SharedValue>:
    SharedValueArray<F>
    + FromRandom
    + Mul<F, Output = Self>
    + for<'a> Mul<&'a F, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
{
}
