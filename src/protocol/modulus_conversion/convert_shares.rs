use crate::bits::BitArray;
use crate::protocol::IpaProtocolStep::ModulusConversion;
use crate::secret_sharing::Arithmetic as ArithmeticSecretSharing;
use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{basics::ZeroPositions, boolean::xor_sparse, context::Context, RecordId},
    secret_sharing::replicated::semi_honest::{
        AdditiveShare as Replicated, XorShare as XorReplicated,
    },
};
use futures::future::try_join_all;
use std::iter::{repeat, zip};

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

impl crate::protocol::Substep for Step {}

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
#[must_use]
pub fn convert_bit_local<F: Field, B: BitArray>(
    helper_role: Role,
    bit_index: u32,
    input: &XorReplicated<B>,
) -> BitConversionTriple<Replicated<F>> {
    let left = u128::from(input.left()[bit_index]);
    let right = u128::from(input.right()[bit_index]);
    BitConversionTriple(match helper_role {
        Role::H1 => [
            Replicated::new(F::from(left), F::ZERO),
            Replicated::new(F::ZERO, F::from(right)),
            Replicated::new(F::ZERO, F::ZERO),
        ],
        Role::H2 => [
            Replicated::new(F::ZERO, F::ZERO),
            Replicated::new(F::from(left), F::ZERO),
            Replicated::new(F::ZERO, F::from(right)),
        ],
        Role::H3 => [
            Replicated::new(F::ZERO, F::from(right)),
            Replicated::new(F::ZERO, F::ZERO),
            Replicated::new(F::from(left), F::ZERO),
        ],
    })
}

#[must_use]
pub fn convert_all_bits_local<F: Field, B: BitArray>(
    helper_role: Role,
    input: &[XorReplicated<B>],
) -> Vec<Vec<BitConversionTriple<Replicated<F>>>> {
    input
        .iter()
        .map(move |record| {
            (0..B::BITS)
                .map(|bit_index: u32| convert_bit_local::<F, B>(helper_role, bit_index, record))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

/// Convert a locally-decomposed single bit into field elements.
/// # Errors
/// Fails only if multiplication fails.
pub async fn convert_bit<F, C, S>(
    ctx: C,
    record_id: RecordId,
    locally_converted_bits: &BitConversionTriple<S>,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
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
pub async fn convert_all_bits<F, C, S>(
    ctx: &C,
    locally_converted_bits: &[Vec<BitConversionTriple<S>>],
    num_bits: u32,
    num_multi_bits: u32,
) -> Result<Vec<Vec<Vec<S>>>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let ctx = ctx.set_total_records(locally_converted_bits.len());

    let all_bits = (0..num_bits as usize).collect::<Vec<_>>();
    try_join_all(all_bits.chunks(num_multi_bits as usize).map(|chunk| {
        try_join_all(
            zip(locally_converted_bits, repeat(ctx.clone()))
                .enumerate()
                .map(|(idx, (record, ctx))| async move {
                    convert_bit_list(
                        ctx.narrow(&ModulusConversion(chunk[0].try_into().unwrap())),
                        &chunk.iter().map(|i| &record[*i]).collect::<Vec<_>>(),
                        RecordId::from(idx),
                    )
                    .await
                }),
        )
    }))
    .await
}

/// # Errors
/// Propagates errors from convert shares
/// # Panics
/// Propagates panics from convert shares
pub async fn convert_bit_list<F, C, S>(
    ctx: C,
    locally_converted_bits: &[&BitConversionTriple<S>],
    record_id: RecordId,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    try_join_all(
        zip(repeat(ctx), locally_converted_bits.iter())
            .enumerate()
            .map(|(i, (ctx, bit))| async move {
                convert_bit(
                    ctx.narrow(&ModulusConversion(i.try_into().unwrap())),
                    record_id,
                    bit,
                )
                .await
            }),
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    use crate::ff::{Field, Fp32BitPrime};
    use crate::helpers::{Direction, Role};
    use crate::protocol::context::Context;
    use crate::protocol::malicious::MaliciousValidator;
    use crate::protocol::MatchKey;
    use crate::rand::thread_rng;
    use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
    use crate::{
        error::Error,
        ff::Fp31,
        protocol::{
            modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple},
            RecordId,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use proptest::prelude::Rng;

    #[tokio::test]
    pub async fn one_bit() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::new().await;
        let match_key = rng.gen::<MatchKey>();
        let result: [Replicated<Fp31>; 3] = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                let triple = convert_bit_local::<Fp31, MatchKey>(ctx.role(), BITNUM, &mk_share);
                convert_bit(ctx.set_total_records(1usize), RecordId::from(0), &triple)
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(Fp31::from(match_key[BITNUM]), result.reconstruct());
    }

    #[tokio::test]
    pub async fn one_bit_malicious() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::new().await;
        let match_key = rng.gen::<MatchKey>();
        let result: [Replicated<Fp31>; 3] = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                let triple = convert_bit_local::<Fp31, MatchKey>(ctx.role(), BITNUM, &mk_share);

                let v = MaliciousValidator::new(ctx);
                let m_ctx = v.context().set_total_records(1);
                let m_triple = m_ctx.upgrade(triple).await.unwrap();
                let m_bit = convert_bit(m_ctx, RecordId::from(0), &m_triple)
                    .await
                    .unwrap();
                v.validate(m_bit).await.unwrap()
            })
            .await;
        assert_eq!(Fp31::from(match_key[BITNUM]), result.reconstruct());
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
        let world = TestWorld::new().await;
        for tweak in TWEAKS {
            let match_key = rng.gen::<MatchKey>();
            world
                .semi_honest(match_key, |ctx, mk_share| async move {
                    let triple =
                        convert_bit_local::<Fp32BitPrime, MatchKey>(ctx.role(), BITNUM, &mk_share);
                    let tweaked = tweak.flip_bit(ctx.role(), triple);

                    let v = MaliciousValidator::new(ctx);
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
