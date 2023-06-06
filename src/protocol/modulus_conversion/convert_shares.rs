use crate::{
    error::Error,
    exact::ExactSizeStream,
    ff::{Field, GaloisField, PrimeField},
    helpers::Role,
    protocol::{
        basics::{SecureMul, ZeroPositions},
        boolean::xor_sparse,
        context::{Context, UpgradeContext, UpgradeToMalicious, UpgradedContext},
        step::IpaProtocolStep,
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        Linear as LinearSecretSharing,
    },
    seq_join::seq_join,
};
use futures::stream::{unfold, Stream, StreamExt};
use pin_project::pin_project;
use std::{
    iter::zip,
    marker::PhantomData,
    ops::Range,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use typenum::Bit;

/// This takes a replicated secret sharing of a sequence of bits (in a packed format)
/// and converts them, one bit-place at a time, to secret sharings of that bit value (either one or zero) in the target field.
///
/// This file is somewhat inspired by Algorithm D.3 from <https://eprint.iacr.org/2018/387.pdf>
/// "Efficient generation of a pair of random shares for small number of parties"
///
/// This protocol takes as input such a 3-way random binary replicated secret-sharing,
/// and produces a 3-party replicated secret-sharing of the same value in a target field
/// of the caller's choosing.
/// Example:
/// For input binary sharing: (0, 1, 1) -> which is a sharing of 0 in `Z_2`
/// sample output in `Z_31` could be: (22, 19, 21) -> also a sharing of 0 in `Z_31`
/// This transformation is simple:
/// The original can be conceived of as r = b0 ⊕ b1 ⊕ b2
/// Each of the 3 bits can be trivially converted into a 3-way secret sharing in `Z_p`
/// So if the second bit is a '1', we can make a 3-way secret sharing of '1' in `Z_p`
/// as (0, 1, 0).
/// Now we simply need to XOR these three sharings together in `Z_p`. This is easy because
/// we know the secret-shared values are all either 0, or 1. As such, the XOR operation
/// is equivalent to fn xor(a, b) { a + b - 2*a*b }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    Xor1,
    Xor2,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::Xor1 => "xor1",
            Self::Xor2 => "xor2",
        }
    }
}

pub struct BitConversionTriple<S>(pub(crate) [S; 3]);

impl<F: PrimeField> BitConversionTriple<Replicated<F>> {
    /// Convert one bit of an XOR sharing into a triple of replicated sharings of that bit.
    /// This is not a usable construct, but it can be used with `convert_one_bit` to produce
    /// a single replicated sharing of that bit.
    ///
    /// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
    ///
    /// # Panics
    /// If any bits in the bitwise shared input cannot be converted into the given field `F`
    /// without truncation or if the bit index is out of range for `B`.
    #[must_use]
    pub fn new(helper_role: Role, left: bool, right: bool) -> Self {
        let left = F::try_from(u128::from(left)).unwrap();
        let right = F::try_from(u128::from(right)).unwrap();
        Self(match helper_role {
            Role::H1 => [
                Replicated::new(left, F::ZERO),
                Replicated::new(F::ZERO, right),
                Replicated::new(F::ZERO, F::ZERO),
            ],
            Role::H2 => [
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(left, F::ZERO),
                Replicated::new(F::ZERO, right),
            ],
            Role::H3 => [
                Replicated::new(F::ZERO, right),
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(left, F::ZERO),
            ],
        })
    }
}

pub trait ToBitConversionTriples {
    /// Get the maximum number of bits that can be produced for this type.
    fn bits(&self) -> u32;

    /// Produce a `BitConversionTriple` for the given role and bit index.
    fn triple<F: PrimeField>(&self, role: Role, i: u32) -> BitConversionTriple<Replicated<F>>;

    fn triple_range<F, I>(&self, role: Role, indices: I) -> Vec<BitConversionTriple<Replicated<F>>>
    where
        F: PrimeField,
        I: IntoIterator<Item = u32>,
    {
        indices
            .into_iter()
            .map(|i| self.triple(role, i))
            .collect::<Vec<_>>()
    }
}

impl<B: GaloisField> ToBitConversionTriples for Replicated<B> {
    fn bits(&self) -> u32 {
        B::BITS
    }

    fn triple<F: PrimeField>(&self, role: Role, i: u32) -> BitConversionTriple<Replicated<F>> {
        BitConversionTriple::new(role, self.left()[i], self.right()[i])
    }
}

#[pin_project]
pub struct LocalBitConverter<F, V, S>
where
    F: PrimeField,
    V: ToBitConversionTriples,
    S: Stream<Item = V> + Send,
{
    role: Role,
    #[pin]
    input: S,
    bits: Range<u32>,
    _f: PhantomData<F>,
}

impl<F, V, S> LocalBitConverter<F, V, S>
where
    F: PrimeField,
    V: ToBitConversionTriples,
    S: Stream<Item = V> + Send,
{
    pub fn new(role: Role, input: S, bits: Range<u32>) -> Self {
        Self {
            role,
            input,
            bits,
            _f: PhantomData,
        }
    }
}

impl<F, V, S> Stream for LocalBitConverter<F, V, S>
where
    F: PrimeField,
    V: ToBitConversionTriples,
    S: Stream<Item = V> + Send,
{
    type Item = Vec<BitConversionTriple<Replicated<F>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match this.input.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => Poll::Ready(Some(input.triple_range(self.role, self.bits))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.input.size_hint()
    }
}

impl<F, V, S> ExactSizeStream for LocalBitConverter<F, V, S>
where
    F: PrimeField,
    V: ToBitConversionTriples,
    S: Stream<Item = V> + Send,
{
}

/// Convert a locally-decomposed single bit into field elements.
/// # Errors
/// Fails only if multiplication fails.
async fn convert_bit<F, C, S>(
    ctx: C,
    record_id: RecordId,
    locally_converted_bits: &BitConversionTriple<S>,
) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
{
    let (sh0, sh1, sh2) = (
        &locally_converted_bits.0[0],
        &locally_converted_bits.0[1],
        &locally_converted_bits.0[2],
    );
    let ctx1 = ctx.narrow(&Step::Xor1);
    let ctx2 = ctx.narrow(&Step::Xor2);
    let sh0_xor_sh1 = xor_sparse(ctx1, record_id, sh0, sh1, ZeroPositions::AVZZ_BZVZ).await?;
    debug_assert_eq!(
        ZeroPositions::mul_output(ZeroPositions::AVZZ_BZVZ),
        ZeroPositions::Pvvz
    );
    xor_sparse(ctx2, record_id, &sh0_xor_sh1, sh2, ZeroPositions::AVVZ_BZZV).await
}

/// Perform modulus conversion.
///
/// This takes a stream of simple (as in semi-honest or without an extension) replicated `GaloisField` shares.
/// It produces a stream of lists of duplicate (as in malicious or with extension) replicated `PrimeField` shares.
/// Each value in the produced list (or `Vec`) corresponds to a single bit of the input value.
///
/// The output values are upgraded into the `UpgradedContext` that is provided.  The caller is responsible for
/// validating the MAC that this process adds these values to.
///
/// # Errors
/// Propagates errors from convert shares
/// # Panics
/// Propagates panics from convert shares
pub fn convert_some_bits<F, V, C, S, VS>(
    ctx: C,
    binary_shares: VS,
    bit_range: Range<u32>,
) -> impl Stream<Item = Result<Vec<S>, Error>>
where
    F: PrimeField,
    V: ToBitConversionTriples,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + SecureMul<C>,
    VS: Stream<Item = V> + Unpin + Send,
    for<'u> UpgradeContext<'u, C, F>:
        UpgradeToMalicious<'u, BitConversionTriple<Replicated<F>>, BitConversionTriple<C::Share>>,
{
    let active = ctx.active_work();
    let locally_converted = LocalBitConverter::new(ctx.role(), binary_shares, bit_range);

    let stream = unfold(
        (ctx, locally_converted, RecordId::FIRST),
        |(ctx, mut locally_converted, record_id)| async move {
            let Some(triple) = locally_converted.next().await else { return None; };
            let converted = ctx.parallel_join(
                zip(
                    (0..).map(|i| ctx.narrow(&IpaProtocolStep::ModulusConversion(i))),
                    triple,
                )
                .map(|(ctx, triple)| async move {
                    let upgraded = ctx.upgrade_for(record_id, triple).await?;
                    convert_bit(ctx, record_id, &upgraded).await
                }),
            );
            Some((converted, (ctx, locally_converted, record_id + 1)))
        },
    );
    seq_join(active, stream)
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::{Direction, Role},
        protocol::{
            context::{Context, UpgradableContext, UpgradedContext, Validator},
            modulus_conversion::{convert_some_bits, BitConversionTriple, LocalBitConverter},
            MatchKey, RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::replicated::{
            semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use futures::stream::{once, StreamExt, TryStreamExt};
    use std::future::ready;

    #[tokio::test]
    pub async fn one_bit() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::default();
        let match_key = rng.gen::<MatchKey>();
        let result: [Replicated<Fp31>; 3] = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                let v = ctx.validator();
                let bits = convert_some_bits(v.context(), once(ready(mk_share)), 0..1)
                    .try_collect::<Vec<_>>()
                    .await
                    .unwrap();
                assert_eq!(bits.len(), 1);
                bits[0][0]
            })
            .await;
        assert_eq!(Fp31::truncate_from(match_key[BITNUM]), result.reconstruct());
    }

    #[tokio::test]
    pub async fn one_bit_malicious() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::default();
        let match_key = rng.gen::<MatchKey>();
        let result: [Replicated<Fp31>; 3] = world
            .malicious(match_key, |ctx, mk_share| async move {
                let v = ctx.validator();
                let m_bit = convert_some_bits(v.context(), once(ready(mk_share)), 0..1)
                    .try_collect::<Vec<_>>()
                    .await
                    .unwrap();
                assert_eq!(m_bit.len(), 1);
                v.validate(m_bit[0][0]).await.unwrap()
            })
            .await;
        assert_eq!(Fp31::truncate_from(match_key[BITNUM]), result.reconstruct());
    }

    #[tokio::test]
    pub async fn one_bit_malicious_tweaks() {
        struct Tweak {
            role: Role,
            index: usize,
            dir: Direction,
        }
        impl Tweak {
            fn flip_bit<F: Field>(
                &self,
                role: Role,
                mut triple: BitConversionTriple<Replicated<F>>,
            ) -> BitConversionTriple<Replicated<F>> {
                if role != self.role {
                    return triple;
                }
                let v = &mut triple.0[self.index];
                *v = match self.dir {
                    Direction::Left => Replicated::new(F::ONE - v.left(), v.right()),
                    Direction::Right => Replicated::new(v.left(), F::ONE - v.right()),
                };
                triple
            }
        }
        const fn t(role: Role, index: usize, dir: Direction) -> Tweak {
            Tweak { role, index, dir }
        }

        const TWEAKS: &[Tweak] = &[
            t(Role::H1, 0, Direction::Left),
            t(Role::H1, 1, Direction::Right),
            t(Role::H2, 1, Direction::Left),
            t(Role::H2, 2, Direction::Right),
            t(Role::H3, 2, Direction::Left),
            t(Role::H3, 0, Direction::Right),
        ];
        const BITNUM: u32 = 4;

        let mut rng = thread_rng();
        let world = TestWorld::default();
        for tweak in TWEAKS {
            let match_key = rng.gen::<MatchKey>();
            world
                .malicious(match_key, |ctx, mk_share| async move {
                    let triples = LocalBitConverter::<Fp32BitPrime, Replicated<MatchKey>, _>::new(
                        ctx.role(),
                        once(ready(mk_share)),
                        0..1,
                    )
                    .collect::<Vec<_>>()
                    .await;
                    let tweaked = tweak.flip_bit(ctx.role(), triples.remove(0).remove(0));

                    let v = ctx.validator();
                    let m_ctx = v.context().set_total_records(1);
                    let m_triple = m_ctx.upgrade(tweaked).await.unwrap();
                    let m_bit = super::convert_bit(m_ctx, RecordId::from(0), &m_triple)
                        .await
                        .unwrap();
                    let err = v
                        .validate(m_bit)
                        .await
                        .expect_err("This should fail validation");
                    assert!(matches!(err, Error::MaliciousSecurityCheckFailed));
                })
                .await;
        }
    }
}
