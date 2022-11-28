use crate::ff::Field;
use crate::protocol::context::MaliciousContext;
use crate::protocol::RecordId;
use crate::rand::thread_rng;
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};
use std::borrow::Borrow;
use std::iter::{repeat, zip};

pub trait IntoShares<T>: Sized {
    fn share(self) -> [T; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [T; 3];
}

impl<F> IntoShares<Replicated<F>> for F
where
    F: Field,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Replicated<F>; 3] {
        share(self, rng)
    }
}

impl<V, T> IntoShares<Vec<T>> for Vec<V>
where
    V: IntoShares<T>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<T>; 3] {
        let mut res = [
            Vec::with_capacity(self.len()),
            Vec::with_capacity(self.len()),
            Vec::with_capacity(self.len()),
        ];
        for v in self {
            for (i, s) in v.share_with(rng).into_iter().enumerate() {
                res[i].push(s);
            }
        }
        res
    }
}

// TODO: make a macro so we can use arbitrary-sized tuples
impl<V, W, T> IntoShares<(T, T)> for (V, W)
where
    V: IntoShares<T>,
    W: IntoShares<T>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(T, T); 3] {
        let [a0, a1, a2] = self.0.share_with(rng);
        let [b0, b1, b2] = self.1.share_with(rng);
        [(a0, b0), (a1, b1), (a2, b2)]
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

impl<F: Field, T: Borrow<Replicated<F>>> Reconstruct<F> for (T, T, T) {
    fn reconstruct(&self) -> F {
        [self.0.borrow(), self.1.borrow(), self.2.borrow()].reconstruct()
    }
}

impl<I, T> Reconstruct<Vec<T>> for [Vec<I>; 3]
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

pub trait ValidateMalicious<F> {
    fn validate(&self, r: F);
}

impl<F, T> ValidateMalicious<F> for [T; 3]
where
    F: Field,
    T: Borrow<MaliciousReplicated<F>>,
{
    fn validate(&self, r: F) {
        use crate::secret_sharing::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let x = (
            self[0].borrow().x().access_without_downgrade(),
            self[1].borrow().x().access_without_downgrade(),
            self[2].borrow().x().access_without_downgrade(),
        );
        let rx = (
            self[0].borrow().rx(),
            self[1].borrow().rx(),
            self[2].borrow().rx(),
        );
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
