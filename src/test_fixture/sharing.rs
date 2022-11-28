use crate::ff::{Field, Int};
use crate::protocol::context::MaliciousContext;
use crate::protocol::RecordId;
use crate::secret_sharing::{
    MaliciousReplicated, Replicated, ThisCodeIsAuthorizedToDowngradeFromMalicious,
};
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};
use rand::thread_rng;
use rand::{
    distributions::{Distribution, Standard},
    Rng, RngCore,
};
use std::iter::{repeat, zip};

use super::{MaliciousShares, ReplicatedShares};

pub trait IntoShares<S>: Sized {
    fn share(self) -> [S; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [S; 3];
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

impl<F> IntoShares<(Replicated<F>, Replicated<F>)> for (F, F)
where
    F: Field,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(Replicated<F>, Replicated<F>); 3] {
        let [x0, x1, x2] = share(self.0, rng);
        let [y0, y1, y2] = share(self.1, rng);
        [(x0, y0), (x1, y1), (x2, y2)]
    }
}

impl<F, V> IntoShares<Vec<Replicated<F>>> for V
where
    F: Field,
    Standard: Distribution<F>,
    V: IntoIterator<Item = F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<Replicated<F>>; 3] {
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

impl<F, V, U> IntoShares<(Vec<Replicated<F>>, Vec<Replicated<F>>)> for (V, U)
where
    F: Field,
    Standard: Distribution<F>,
    V: IntoIterator<Item = F>,
    U: IntoIterator<Item = F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(Vec<Replicated<F>>, Vec<Replicated<F>>); 3] {
        let ([res11, res12, res13], [res21, res22, res23]) = (
            self.0.into_iter().share_with(rng),
            self.1.into_iter().share_with(rng),
        );
        [(res11, res21), (res12, res22), (res13, res23)]
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

/// Take a field value `x` and turn them into replicated bitwise sharings of three
pub fn shared_bits<F: Field, R: RngCore>(x: F, rand: &mut R) -> Vec<[Replicated<F>; 3]>
where
    Standard: Distribution<F>,
{
    let x = x.as_u128();
    (0..F::Integer::BITS)
        .map(|i| share(F::from((x >> i) & 1), rand))
        .collect::<Vec<_>>()
}

/// Validates correctness of the secret sharing scheme.
///
/// # Panics
/// Panics if the given input is not a valid replicated secret share.
pub fn validate_and_reconstruct<F: Field>(
    s0: &Replicated<F>,
    s1: &Replicated<F>,
    s2: &Replicated<F>,
) -> F {
    assert_eq!(
        s0.left() + s1.left() + s2.left(),
        s0.right() + s1.right() + s2.right()
    );

    assert_eq!(s0.right(), s1.left());
    assert_eq!(s1.right(), s2.left());
    assert_eq!(s2.right(), s0.left());

    s0.left() + s1.left() + s2.left()
}

/// Validates correctness of the secret sharing scheme.
///
/// # Panics
/// Panics if the given input is not a valid replicated secret share.
pub fn validate_and_reconstruct_malicious<F: Field>(
    s0: &MaliciousReplicated<F>,
    s1: &MaliciousReplicated<F>,
    s2: &MaliciousReplicated<F>,
) -> (F, F) {
    let result = validate_and_reconstruct(
        s0.x().access_without_downgrade(),
        s1.x().access_without_downgrade(),
        s2.x().access_without_downgrade(),
    );
    let result_macs = validate_and_reconstruct(s0.rx(), s1.rx(), s2.rx());

    (result, result_macs)
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
        let revealed = validate_and_reconstruct(&result[0][i], &result[1][i], &result[2][i]);
        assert_eq!(revealed, F::from(*expected));
    }
}

/// Validates expected result from the secret shares obtained.
///
/// # Panics
/// Panics if the expected result is not same as obtained result. Also panics if `validate_and_reconstruct` fails for input or MACs
pub fn validate_list_of_shares_malicious<F: Field>(
    r: F,
    expected_result: &[u128],
    result: &MaliciousShares<F>,
) {
    assert_eq!(expected_result.len(), result[0].len());
    assert_eq!(expected_result.len(), result[1].len());
    assert_eq!(expected_result.len(), result[2].len());
    for (i, expected) in expected_result.iter().enumerate() {
        let (revealed, revealed_times_r) =
            validate_and_reconstruct_malicious(&result[0][i], &result[1][i], &result[2][i]);
        assert_eq!(revealed, F::from(*expected));
        assert_eq!(revealed * r, revealed_times_r);
    }
}
