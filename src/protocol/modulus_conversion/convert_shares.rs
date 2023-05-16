use crate::{
    error::Error,
    exact::ExactSizeStream,
    ff::{Field, GaloisField},
    helpers::Role,
    protocol::{
        basics::{SecureMul, ZeroPositions},
        boolean::xor_sparse,
        context::Context,
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
    iter::{repeat, zip},
    marker::PhantomData,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

///! This takes a replicated secret sharing of a sequence of bits (in a packed format)
///! and converts them, one bit-place at a time, to secret sharings of that bit value (either one or zero) in the target field.
///!
///! This file is somewhat inspired by Algorithm D.3 from <https://eprint.iacr.org/2018/387.pdf>
///! "Efficient generation of a pair of random shares for small number of parties"
///!
///! This protocol takes as input such a 3-way random binary replicated secret-sharing,
///! and produces a 3-party replicated secret-sharing of the same value in a target field
///! of the caller's choosing.
///! Example:
///! For input binary sharing: (0, 1, 1) -> which is a sharing of 0 in `Z_2`
///! sample output in `Z_31` could be: (22, 19, 21) -> also a sharing of 0 in `Z_31`
///! This transformation is simple:
///! The original can be conceived of as r = b0 ⊕ b1 ⊕ b2
///! Each of the 3 bits can be trivially converted into a 3-way secret sharing in `Z_p`
///! So if the second bit is a '1', we can make a 3-way secret sharing of '1' in `Z_p`
///! as (0, 1, 0).
///! Now we simply need to XOR these three sharings together in `Z_p`. This is easy because
///! we know the secret-shared values are all either 0, or 1. As such, the XOR operation
///! is equivalent to fn xor(a, b) { a + b - 2*a*b }
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

/// Convert one bit of an XOR sharing into a triple of replicated sharings of that bit.
/// This is not a usable construct, but it can be used with `convert_one_bit` to produce
/// a single replicated sharing of that bit.
///
/// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
///
/// # Panics
/// If any bits in the bitwise shared input cannot be converted into the given field `F`
/// without truncation.
#[must_use]
pub fn convert_bit_local<F: Field, B: GaloisField>(
    helper_role: Role,
    bit_index: u32,
    input: &Replicated<B>,
) -> BitConversionTriple<Replicated<F>> {
    let left = u128::from(input.left()[bit_index]);
    let right = u128::from(input.right()[bit_index]);
    BitConversionTriple(match helper_role {
        Role::H1 => [
            Replicated::new(F::try_from(left).unwrap(), F::ZERO),
            Replicated::new(F::ZERO, F::try_from(right).unwrap()),
            Replicated::new(F::ZERO, F::ZERO),
        ],
        Role::H2 => [
            Replicated::new(F::ZERO, F::ZERO),
            Replicated::new(F::try_from(left).unwrap(), F::ZERO),
            Replicated::new(F::ZERO, F::try_from(right).unwrap()),
        ],
        Role::H3 => [
            Replicated::new(F::ZERO, F::try_from(right).unwrap()),
            Replicated::new(F::ZERO, F::ZERO),
            Replicated::new(F::try_from(left).unwrap(), F::ZERO),
        ],
    })
}

#[pin_project]
pub struct LocalBitConverter<F, B, S>
where
    F: Field,
    B: GaloisField,
    S: Stream<Item = Replicated<B>>,
{
    role: Role,
    #[pin]
    input: S,
    _f: PhantomData<F>,
}

impl<F, B, S> LocalBitConverter<F, B, S>
where
    F: Field,
    B: GaloisField,
    S: Stream<Item = Replicated<B>>,
{
    pub fn new(role: Role, input: S) -> Self {
        Self {
            role,
            input,
            _f: PhantomData,
        }
    }
}

impl<F, B, S> Stream for LocalBitConverter<F, B, S>
where
    F: Field,
    B: GaloisField,
    S: Stream<Item = Replicated<B>> + Send,
{
    type Item = Vec<BitConversionTriple<Replicated<F>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match this.input.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => Poll::Ready(Some(
                (0..B::BITS)
                    .map(|bit_index: u32| convert_bit_local::<F, B>(*this.role, bit_index, &input))
                    .collect::<Vec<_>>(),
            )),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.input.size_hint()
    }
}

impl<F, B, S> ExactSizeStream for LocalBitConverter<F, B, S>
where
    F: Field,
    B: GaloisField,
    S: Stream<Item = Replicated<B>> + Send + ExactSizeStream,
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

/// # Errors
/// Propagates errors from convert shares
/// # Panics
/// Propagates panics from convert shares
pub async fn convert_all_bits<F, B, C, S, LS>(
    ctx: &C,
    locally_converted_bits: LS,
) -> impl Stream<Item = Result<Vec<S>, Error>>
where
    F: Field,
    B: GaloisField,
    C: Context + 'static,
    S: LinearSecretSharing<F> + SecureMul<C>,
    LS: Stream<Item = Vec<BitConversionTriple<S>>> + ExactSizeStream + Unpin + Send,
{
    let active = ctx.active_work();
    let ctx = ctx.set_total_records(locally_converted_bits.len());

    let stream = unfold(
        (ctx, locally_converted_bits, RecordId::FIRST),
        |(ctx, mut locally_converted_bits, record_id)| async move {
            let Some(triples) = locally_converted_bits.next().await else { return None; };
            let converted = ctx.parallel_join(
                zip(
                    (0..B::BITS).map(|i| ctx.narrow(&IpaProtocolStep::ModulusConversion(i))),
                    triples,
                )
                .map(|(ctx, bit)| async move { convert_bit(ctx, record_id, &bit).await }),
            );
            Some((converted, (ctx, locally_converted_bits, record_id + 1)))
        },
    );
    seq_join(active, stream)
}

/// # Errors
/// Propagates errors from convert shares
/// # Panics
/// Propagates panics from convert shares
pub async fn convert_bit_list<F, C, S>(
    ctx: &C,
    locally_converted_bits: &[&BitConversionTriple<S>],
    record_id: RecordId,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
{
    // True concurrency needed here (different contexts).
    ctx.parallel_join(
        zip(repeat(ctx.clone()), locally_converted_bits.iter())
            .enumerate()
            .map(|(i, (ctx, bit))| async move {
                convert_bit(
                    ctx.narrow(&IpaProtocolStep::ModulusConversion(i.try_into().unwrap())),
                    record_id,
                    bit,
                )
                .await
            }),
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::{Direction, Role},
        protocol::{
            context::{Context, UpgradableContext, UpgradedContext, Validator},
            modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple},
            MatchKey, RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::replicated::{
            semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn one_bit() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::default();
        let match_key = rng.gen::<MatchKey>();
        let result: [Replicated<Fp31>; 3] = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                let triple = convert_bit_local::<Fp31, MatchKey>(ctx.role(), BITNUM, &mk_share);
                convert_bit(ctx.set_total_records(1usize), RecordId::from(0), &triple)
                    .await
                    .unwrap()
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
                let triple = convert_bit_local::<Fp31, MatchKey>(ctx.role(), BITNUM, &mk_share);

                let v = ctx.validator();
                let m_ctx = v.context().set_total_records(1);
                let m_triple = m_ctx.upgrade(triple).await.unwrap();
                let m_bit = convert_bit(m_ctx, RecordId::from(0), &m_triple)
                    .await
                    .unwrap();
                v.validate(m_bit).await.unwrap()
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
                    let triple =
                        convert_bit_local::<Fp32BitPrime, MatchKey>(ctx.role(), BITNUM, &mk_share);
                    let tweaked = tweak.flip_bit(ctx.role(), triple);

                    let v = ctx.validator();
                    let m_ctx = v.context().set_total_records(1);
                    let m_triple = m_ctx.upgrade(tweaked).await.unwrap();
                    let m_bit = convert_bit(m_ctx, RecordId::from(0), &m_triple)
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
