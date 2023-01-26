use crate::bits::BitArray;
use crate::ff::Field;
use crate::protocol::boolean::RandomBitsShare;
use crate::secret_sharing::{
    replicated::malicious::AdditiveShare as MaliciousReplicated,
    replicated::semi_honest::{AdditiveShare as Replicated, XorShare as XorReplicated},
    SecretSharing,
};
use std::borrow::Borrow;
use std::iter::zip;

/// Deconstructs a value into N values, one for each bit.
pub fn into_bits<F: Field>(x: F) -> Vec<F> {
    (0..(128 - F::PRIME.into().leading_zeros()))
        .map(|i| F::from((x.as_u128() >> i) & 1))
        .collect::<Vec<_>>()
}

/// Deconstructs a value into N values, one for each bi3t.
/// # Panics
/// It won't
#[must_use]
pub fn get_bits<F: Field>(x: u32, num_bits: u32) -> Vec<F> {
    (0..num_bits.try_into().unwrap())
        .map(|i| F::from(((x >> i) & 1).into()))
        .collect::<Vec<_>>()
}

/// A trait that is helpful for reconstruction of values in tests.
pub trait Reconstruct<T> {
    /// Validates correctness of the secret sharing scheme.
    ///
    /// # Panics
    /// Panics if the given input is not a valid replicated secret share.
    fn reconstruct(&self) -> T;
}

impl<F: Field> Reconstruct<F> for [&Replicated<F>; 3] {
    fn reconstruct(&self) -> F {
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

impl<F: Field> Reconstruct<F> for [Replicated<F>; 3] {
    fn reconstruct(&self) -> F {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<B: BitArray> Reconstruct<B> for [&XorReplicated<B>; 3] {
    fn reconstruct(&self) -> B {
        let s0 = &self[0];
        let s1 = &self[1];
        let s2 = &self[2];

        assert_eq!(
            s0.left() ^ s1.left() ^ s2.left(),
            s0.right() ^ s1.right() ^ s2.right(),
        );

        assert_eq!(s0.right(), s1.left());
        assert_eq!(s1.right(), s2.left());
        assert_eq!(s2.right(), s0.left());

        s0.left() ^ s1.left() ^ s2.left()
    }
}

impl<B: BitArray> Reconstruct<B> for [XorReplicated<B>; 3] {
    fn reconstruct(&self) -> B {
        [&self[0], &self[1], &self[2]].reconstruct()
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

impl<I, T> Reconstruct<T> for [Vec<I>; 3]
where
    for<'v> [&'v Vec<I>; 3]: Reconstruct<T>,
{
    fn reconstruct(&self) -> T {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<I, T> Reconstruct<Vec<T>> for [&Vec<I>; 3]
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

impl<F, S> Reconstruct<F> for [RandomBitsShare<F, S>; 3]
where
    F: Field,
    S: SecretSharing<F>,
    for<'a> [&'a S; 3]: Reconstruct<F>,
{
    fn reconstruct(&self) -> F {
        let bits = zip(
            self[0].b_b.iter(),
            zip(self[1].b_b.iter(), self[2].b_b.iter()),
        )
        .enumerate()
        .map(|(i, (b0, (b1, b2)))| [b0, b1, b2].reconstruct() * F::from(1 << i))
        .fold(F::ZERO, |a, b| a + b);
        let value = [&self[0].b_p, &self[1].b_p, &self[2].b_p].reconstruct();
        assert_eq!(bits, value);
        value
    }
}

pub trait ValidateMalicious<F> {
    fn validate(&self, r: F);
}

impl<F, T> ValidateMalicious<F> for [T; 3]
where
    F: Field,
    T: Borrow<MaliciousReplicated<F>>,
{
    fn validate(&self, r: F) {
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
        assert_eq!(x.reconstruct() * r, rx.reconstruct());
    }
}

impl<F: Field> ValidateMalicious<F> for [Vec<MaliciousReplicated<F>>; 3] {
    fn validate(&self, r: F) {
        assert_eq!(self[0].len(), self[1].len());
        assert_eq!(self[0].len(), self[2].len());

        for (m0, (m1, m2)) in zip(self[0].iter(), zip(self[1].iter(), self[2].iter())) {
            [m0, m1, m2].validate(r);
        }
    }
}

impl<F: Field> ValidateMalicious<F> for [(MaliciousReplicated<F>, Vec<MaliciousReplicated<F>>); 3] {
    fn validate(&self, r: F) {
        let [t0, t1, t2] = self;
        let ((s0, v0), (s1, v1), (s2, v2)) = (t0, t1, t2);

        [s0, s1, s2].validate(r);
        [v0.clone(), v1.clone(), v2.clone()].validate(r);
    }
}
