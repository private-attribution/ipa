use crate::ff::Field;
use crate::protocol::context::MaliciousContext;
use crate::protocol::{BitOpStep, RecordId, Substep};
use crate::rand::thread_rng;
use crate::secret_sharing::{MaliciousReplicated, Replicated, XorReplicated};
use async_trait::async_trait;
use futures::future::{join, try_join_all};
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};
use std::borrow::Borrow;
use std::iter::{repeat, zip};

#[derive(Clone, Copy)]
pub struct MaskedMatchKey(u64);

impl MaskedMatchKey {
    pub const BITS: u32 = 23;
    const MASK: u64 = u64::MAX >> (64 - Self::BITS);

    #[must_use]
    pub fn mask(v: u64) -> Self {
        Self(v & Self::MASK)
    }

    #[must_use]
    pub fn bit(self, bit_num: u32) -> u64 {
        (self.0 >> bit_num) & 1
    }
}

impl From<MaskedMatchKey> for u64 {
    fn from(v: MaskedMatchKey) -> Self {
        v.0
    }
}

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

impl<U, V, T> IntoShares<Vec<T>> for V
where
    U: IntoShares<T>,
    V: IntoIterator<Item = U>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<T>; 3] {
        let it = self.into_iter();
        let (lower_bound, upper_bound) = it.size_hint();
        let len = upper_bound.unwrap_or(lower_bound);
        let mut res = [
            Vec::with_capacity(len),
            Vec::with_capacity(len),
            Vec::with_capacity(len),
        ];
        for u in it {
            for (i, s) in u.share_with(rng).into_iter().enumerate() {
                res[i].push(s);
            }
        }
        res
    }
}

// TODO: make a macro so we can use arbitrary-sized tuples
impl<T, U, V, W> IntoShares<(T, U)> for (V, W)
where
    T: Sized,
    U: Sized,
    V: IntoShares<T>,
    W: IntoShares<U>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(T, U); 3] {
        let [a0, a1, a2] = self.0.share_with(rng);
        let [b0, b1, b2] = self.1.share_with(rng);
        [(a0, b0), (a1, b1), (a2, b2)]
    }
}

impl IntoShares<XorReplicated> for MaskedMatchKey {
    fn share_with<R: Rng>(self, rng: &mut R) -> [XorReplicated; 3] {
        debug_assert_eq!(self.0, self.0 & Self::MASK);
        let s0 = rng.gen::<u64>() & Self::MASK;
        let s1 = rng.gen::<u64>() & Self::MASK;
        let s2 = self.0 ^ s0 ^ s1;
        [
            XorReplicated::new(s0, s1),
            XorReplicated::new(s1, s2),
            XorReplicated::new(s2, s0),
        ]
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

/// Deconstructs a value into N values, one for each bi3t.
/// # Panics
/// It won't
#[must_use]
pub fn get_bits<F: Field>(x: u32, num_bits: u32) -> Vec<F> {
    (0..num_bits.try_into().unwrap())
        .map(|i| F::from(((x >> i) & 1).into()))
        .collect::<Vec<_>>()
}

/// Default step type for upgrades.
struct IntoMaliciousStep;
impl Substep for IntoMaliciousStep {}
impl AsRef<str> for IntoMaliciousStep {
    fn as_ref(&self) -> &str {
        "malicious_upgrade"
    }
}

/// For upgrading various shapes of replicated share to malicious.
#[async_trait]
pub trait IntoMalicious<F: Field, M>: Sized {
    async fn upgrade(self, ctx: MaliciousContext<'_, F>) -> M {
        self.upgrade_with(ctx, &IntoMaliciousStep).await
    }
    async fn upgrade_with<SS: Substep>(self, ctx: MaliciousContext<'_, F>, step: &SS) -> M;
}

#[async_trait]
impl<F: Field> IntoMalicious<F, MaliciousReplicated<F>> for Replicated<F> {
    async fn upgrade_with<'a, SS: Substep>(
        self,
        ctx: MaliciousContext<'a, F>,
        step: &SS,
    ) -> MaliciousReplicated<F> {
        ctx.upgrade_with(step, RecordId::from(0_u32), self)
            .await
            .unwrap()
    }
}

#[async_trait]
impl<F, T, TM, U, UM> IntoMalicious<F, (TM, UM)> for (T, U)
where
    F: Field,
    T: IntoMalicious<F, TM> + Send,
    U: IntoMalicious<F, UM> + Send,
    TM: Sized + Send,
    UM: Sized + Send,
{
    // Note that this implementation doesn't work with arbitrary nesting.
    // For that, we'd need a `.narrow_for_upgrade()` function on the context.
    async fn upgrade_with<'a, SS: Substep>(
        self,
        ctx: MaliciousContext<'a, F>,
        _step: &SS,
    ) -> (TM, UM) {
        join(
            self.0.upgrade_with(ctx.clone(), &BitOpStep::from(0)),
            self.1.upgrade_with(ctx, &BitOpStep::from(1)),
        )
        .await
    }
}

#[async_trait]
impl<F, I> IntoMalicious<F, Vec<MaliciousReplicated<F>>> for I
where
    F: Field,
    I: IntoIterator<Item = Replicated<F>> + Send,
    <I as IntoIterator>::IntoIter: Send,
{
    // Note that this implementation doesn't work with arbitrary nesting.
    // For that, we'd need a `.narrow_for_upgrade()` function on the context.
    async fn upgrade_with<'a, SS: Substep>(
        self,
        ctx: MaliciousContext<'a, F>,
        step: &SS,
    ) -> Vec<MaliciousReplicated<F>> {
        try_join_all(
            zip(repeat(ctx), self.into_iter().enumerate()).map(|(ctx, (i, share))| async move {
                ctx.upgrade_with(step, RecordId::from(i), share).await
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

impl<F, T, U, V> Reconstruct<F> for (T, U, V)
where
    F: Field,
    T: Borrow<Replicated<F>>,
    U: Borrow<Replicated<F>>,
    V: Borrow<Replicated<F>>,
{
    fn reconstruct(&self) -> F {
        [self.0.borrow(), self.1.borrow(), self.2.borrow()].reconstruct()
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
