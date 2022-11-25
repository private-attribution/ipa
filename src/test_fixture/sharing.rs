use crate::ff::Field;
use crate::protocol::context::MaliciousContext;
use crate::protocol::RecordId;
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};
use rand::thread_rng;
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};
use std::borrow::Borrow;
use std::iter::{repeat, zip};

use super::ReplicatedShares;

pub trait IntoShares: Sized {
    type Output;
    fn share(self) -> [Self::Output; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [Self::Output; 3];
}

impl<F> IntoShares for F
where
    F: Field,
    Standard: Distribution<F>,
{
    type Output = Replicated<F>;
    fn share_with<R: Rng>(self, rng: &mut R) -> [Self::Output; 3] {
        share(self, rng)
    }
}

impl<F, V> IntoShares for Vec<V>
where
    F: Field,
    Standard: Distribution<F>,
    V: IntoShares,
{
    type Output = Vec<<V as IntoShares>::Output>;
    fn share_with<R: Rng>(self, rng: &mut R) -> [Self::Output; 3] {
        let it = self.into_iter();
        let store = if let (_, Some(sz)) = it.size_hint() {
            Vec::with_capacity(sz)
        } else {
            Vec::new()
        };
        let mut res = [store.clone(), store.clone(), store];
        for v in it {
            for (i, s) in share(v, rng).into_iter().enumerate() {
                res[i].push(s);
            }
        }
        res
    }
}

// TODO: make a macro so we can use arbitrary-sized tuples
impl<T> IntoShares for (T, T)
where
    T: IntoShares,
{
    type Output = (<T as IntoShares>::Output, <T as IntoShares>::Output);
    fn share_with<R: Rng>(self, rng: &mut R) -> [Self::Output; 3] {
        (self.0.share_with(rng), self.1.share_with(rng))
    }
}

/// Shares `input` into 3 replicated secret shares using the provided `rng` implementation
pub fn share<F: Field, R: RngCore>(input: F, rng: &mut R) -> [Replicated<F>; 3]
where
    Standard: Distribution<F>,
{
    let x1 = rng.gen::<F>();
    let x2 = rng.gen::<F>();
    let x3 = input - (x1 + x2);

    [
        Replicated::new(x1, x2),
        Replicated::new(x2, x3),
        Replicated::new(x3, x1),
    ]
}

/// Deconstructs a value into N values, one for each bit.
pub fn into_bits<F: Field>(x: F) -> Vec<F> {
    (0..(128 - F::PRIME.into().leading_zeros()) as u32)
        .map(|i| F::from((x.as_u128() >> i) & 1))
        .collect::<Vec<_>>()
}

/// For upgrading various shapes of replicated share to malicious.
#[async_trait]
pub trait IntoMalicious<F: Field, M> {
    async fn upgrade(self, ctx: MaliciousContext<'_, F>) -> M;
}

#[async_trait]
impl<F: Field> IntoMalicious<F, MaliciousReplicated<F>> for Replicated<F> {
    async fn upgrade<'a>(self, ctx: MaliciousContext<'a, F>) -> MaliciousReplicated<F> {
        ctx.upgrade(RecordId::from(0_u32), self).await.unwrap()
    }
}

#[async_trait]
impl<F: Field> IntoMalicious<F, (MaliciousReplicated<F>, MaliciousReplicated<F>)>
    for (Replicated<F>, Replicated<F>)
{
    async fn upgrade<'a>(
        self,
        ctx: MaliciousContext<'a, F>,
    ) -> (MaliciousReplicated<F>, MaliciousReplicated<F>) {
        try_join(
            ctx.upgrade(RecordId::from(0_u32), self.0),
            ctx.upgrade(RecordId::from(1_u32), self.1),
        )
        .await
        .unwrap()
    }
}

#[async_trait]
impl<F, I> IntoMalicious<F, Vec<MaliciousReplicated<F>>> for I
where
    F: Field,
    I: IntoIterator<Item = Replicated<F>> + Send,
    <I as IntoIterator>::IntoIter: Send,
{
    async fn upgrade<'a>(self, ctx: MaliciousContext<'a, F>) -> Vec<MaliciousReplicated<F>> {
        try_join_all(
            zip(repeat(ctx), self.into_iter().enumerate()).map(|(ctx, (i, share))| async move {
                ctx.upgrade(RecordId::from(i), share).await
            }),
        )
        .await
        .unwrap()
    }
}

/// A trait that is helpful for reconstruction of values in tests.
pub trait Reconstruct<T> {
    /// Validates correctness of the secret sharing scheme.
    ///
    /// # Panics
    /// Panics if the given input is not a valid replicated secret share.
    fn reconstruct(&self) -> T;
}

impl<F: Field, T: Borrow<Replicated<F>>> Reconstruct<F> for [T; 3] {
    fn reconstruct(&self) -> F {
        let s0 = self[0].borrow();
        let s1 = self[1].borrow();
        let s2 = self[2].borrow();

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

impl<F: Field, T: Borrow<Replicated<F>>> Reconstruct<F> for (T, T, T) {
    fn reconstruct(&self) -> F {
        [self.0, self.1, self.2].reconstruct()
    }
}

impl<I: Reconstruct<T>, T> Reconstruct<Vec<T>> for [Vec<I>; 3] {
    fn reconstruct(&self) -> Vec<T> {
        zip(self[0].iter(), zip(self[1].iter(), self[2].iter()))
            .map(|(x0, (x1, x2))| [x0, x1, x2].reconstruct())
            .collect()
    }
}

pub trait ValidateMalicious<F> {
    fn validate(&self, r: F);
}

impl<F: Field> ValidateMalicious<F> for [&MaliciousReplicated<F>; 3] {
    fn validate(&self, r: F) {
        use crate::secret_sharing::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let x = (
            self[0].x().access_without_downgrade(),
            self[1].x().access_without_downgrade(),
            self[2].x().access_without_downgrade(),
        )
            .reconstruct();
        let rx = (self[0].rx(), self[1].rx(), self[1].rx()).reconstruct();
        assert_eq!(x * r, rx);
    }
}

/// Validates expected result from the secret shares obtained.
///
/// # Panics
/// Panics if the expected result is not same as obtained result. Also panics if `validate_and_reconstruct` fails
pub fn validate_list_of_shares<F: Field>(expected_result: &[u128], result: &ReplicatedShares<F>) {
    assert_eq!(expected_result.len(), result[0].len());
    assert_eq!(expected_result.len(), result[1].len());
    assert_eq!(expected_result.len(), result[2].len());
    for (i, expected) in expected_result.iter().enumerate() {
        let revealed = (&result[0][i], &result[1][i], &result[2][i]).reconstruct();
        assert_eq!(revealed, F::from(*expected));
    }
}
