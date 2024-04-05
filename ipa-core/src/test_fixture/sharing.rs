use std::{borrow::Borrow, iter::zip, ops::Deref};

use crate::{
    ff::{Field, PrimeField, U128Conversions},
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        BitDecomposed, SharedValue, Vectorizable,
    },
};

/// Deconstructs a field value into N values, one for each bit.
///
/// The bit width is determined based on the field type.
pub fn into_bits<F: PrimeField + U128Conversions>(v: F) -> BitDecomposed<F> {
    BitDecomposed::decompose(u128::BITS - F::PRIME.into().leading_zeros(), |i| {
        F::truncate_from((v.as_u128() >> i) & 1)
    })
}

/// Deconstructs a value into N values, one for each bit.
///
/// The bit width is specified explicitly.
#[must_use]
pub fn get_bits<V: U128Conversions>(x: u32, num_bits: u32) -> BitDecomposed<V> {
    BitDecomposed::decompose(num_bits, |i| V::truncate_from((x >> i) & 1))
}

/// A trait that is helpful for reconstruction of values in tests.
pub trait Reconstruct<T> {
    /// Validates correctness of the secret sharing scheme.
    ///
    /// # Panics
    /// Panics if the given input is not a valid replicated secret share.
    fn reconstruct(&self) -> T;
}

/// Alternate version of `Reconstruct` for vectors.
///
/// There is no difference in the traits, but this avoids having to add
/// type annotations everywhere to disambiguate whether a single-bit
/// result should be reconstructed as `F` or `[F; 1]`.
pub trait ReconstructArr<T> {
    /// Validates correctness of the secret sharing scheme.
    ///
    /// # Panics
    /// Panics if the given input is not a valid replicated secret share.
    fn reconstruct_arr(&self) -> T;
}

impl<V: SharedValue> Reconstruct<V> for [&Replicated<V>; 3] {
    fn reconstruct(&self) -> V {
        let s0 = &self[0];
        let s1 = &self[1];
        let s2 = &self[2];

        assert_eq!(
            s0.left() + s1.left() + s2.left(),
            s0.right() + s1.right() + s2.right(),
        );

        assert_eq!(s0.right(), s1.left());
        assert_eq!(s1.right(), s2.left());
        assert_eq!(s2.right(), s0.left());

        s0.left() + s1.left() + s2.left()
    }
}

impl<V: SharedValue> Reconstruct<V> for [Replicated<V>; 3] {
    fn reconstruct(&self) -> V {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<F: Field + Vectorizable<N>, const N: usize> ReconstructArr<<F as Vectorizable<N>>::Array>
    for [Replicated<F, N>; 3]
{
    fn reconstruct_arr(&self) -> <F as Vectorizable<N>>::Array {
        let s0l = self[0].left_arr();
        let s0r = self[0].right_arr();
        let s1l = self[1].left_arr();
        let s1r = self[1].right_arr();
        let s2l = self[2].left_arr();
        let s2r = self[2].right_arr();

        assert_eq!(s0l.clone() + s1l + s2l, s0r.clone() + s1r + s2r);

        assert_eq!(s0r, s1l);
        assert_eq!(s1r, s2l);
        assert_eq!(s2r, s0l);

        s0l.clone() + s1l + s2l
    }
}

impl<T, U, V, W> Reconstruct<(V, W)> for [(T, U); 3]
where
    for<'t> [&'t T; 3]: Reconstruct<V>,
    for<'u> [&'u U; 3]: Reconstruct<W>,
    V: Sized,
    W: Sized,
{
    fn reconstruct(&self) -> (V, W) {
        (
            [&self[0].0, &self[1].0, &self[2].0].reconstruct(),
            [&self[0].1, &self[1].1, &self[2].1].reconstruct(),
        )
    }
}

impl<I, T> Reconstruct<Vec<T>> for [Vec<I>; 3]
where
    for<'v> [&'v [I]; 3]: Reconstruct<Vec<T>>,
{
    fn reconstruct(&self) -> Vec<T> {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<I, T> Reconstruct<BitDecomposed<T>> for [&BitDecomposed<I>; 3]
where
    for<'i> [&'i [I]; 3]: Reconstruct<Vec<T>>,
{
    fn reconstruct(&self) -> BitDecomposed<T> {
        BitDecomposed::new(self.map(Deref::deref).reconstruct())
    }
}

impl<I, T> Reconstruct<Vec<T>> for [&Vec<I>; 3]
where
    for<'i> [&'i [I]; 3]: Reconstruct<Vec<T>>,
{
    fn reconstruct(&self) -> Vec<T> {
        self.map(Deref::deref).reconstruct()
    }
}

impl<I, T> Reconstruct<Vec<T>> for [&[I]; 3]
where
    for<'i> [&'i I; 3]: Reconstruct<T>,
{
    fn reconstruct(&self) -> Vec<T> {
        assert_eq!(self[0].len(), self[1].len());
        assert_eq!(self[0].len(), self[2].len());
        zip(self[0].iter(), zip(self[1].iter(), self[2].iter()))
            .map(|(x0, (x1, x2))| [x0, x1, x2].reconstruct())
            .collect()
    }
}

impl Reconstruct<()> for [(); 3] {
    fn reconstruct(&self) {}
}

#[cfg(feature = "descriptive-gate")]
impl<F, S> Reconstruct<F> for [crate::protocol::boolean::RandomBitsShare<F, S>; 3]
where
    F: Field + U128Conversions,
    S: crate::secret_sharing::SecretSharing<F>,
    for<'a> [&'a S; 3]: Reconstruct<F>,
{
    fn reconstruct(&self) -> F {
        let bits = zip(
            self[0].b_b.iter(),
            zip(self[1].b_b.iter(), self[2].b_b.iter()),
        )
        .enumerate()
        .map(|(i, (b0, (b1, b2)))| [b0, b1, b2].reconstruct() * F::try_from(1 << i).unwrap())
        .fold(F::ZERO, |a, b| a + b);
        let value = [&self[0].b_p, &self[1].b_p, &self[2].b_p].reconstruct();
        assert_eq!(bits, value);
        value
    }
}

pub trait ValidateMalicious<F: ExtendableField> {
    fn validate(&self, r: F::ExtendedField);
}

impl<F, T> ValidateMalicious<F> for [T; 3]
where
    F: ExtendableField,
    T: Borrow<MaliciousReplicated<F>>,
{
    fn validate(&self, r: F::ExtendedField) {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let x = [
            self[0].borrow().x().access_without_downgrade(),
            self[1].borrow().x().access_without_downgrade(),
            self[2].borrow().x().access_without_downgrade(),
        ];
        let rx = [
            self[0].borrow().rx(),
            self[1].borrow().rx(),
            self[2].borrow().rx(),
        ];
        assert_eq!(x.reconstruct().to_extended() * r, rx.reconstruct(),);
    }
}

impl<F: ExtendableField> ValidateMalicious<F> for [&[MaliciousReplicated<F>]; 3] {
    fn validate(&self, r: F::ExtendedField) {
        assert_eq!(self[0].len(), self[1].len());
        assert_eq!(self[0].len(), self[2].len());

        for (m0, (m1, m2)) in zip(self[0].iter(), zip(self[1].iter(), self[2].iter())) {
            [m0, m1, m2].validate(r);
        }
    }
}

impl<F: ExtendableField> ValidateMalicious<F> for [Vec<MaliciousReplicated<F>>; 3] {
    fn validate(&self, r: F::ExtendedField) {
        [&self[0][..], &self[1][..], &self[2][..]].validate(r);
    }
}

impl<F: ExtendableField> ValidateMalicious<F> for [BitDecomposed<MaliciousReplicated<F>>; 3] {
    fn validate(&self, r: F::ExtendedField) {
        [&self[0][..], &self[1][..], &self[2][..]].validate(r);
    }
}

impl<F: ExtendableField> ValidateMalicious<F>
    for [(
        MaliciousReplicated<F>,
        BitDecomposed<MaliciousReplicated<F>>,
    ); 3]
{
    fn validate(&self, r: F::ExtendedField) {
        let [t0, t1, t2] = self;
        let ((s0, v0), (s1, v1), (s2, v2)) = (t0, t1, t2);

        [s0, s1, s2].validate(r);
        [v0.clone(), v1.clone(), v2.clone()].validate(r);
    }
}
