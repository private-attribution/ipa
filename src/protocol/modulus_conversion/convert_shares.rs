use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{context::Context, RecordId},
    secret_sharing::{Replicated, SecretSharing, XorReplicated},
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

/// Convert one bit of an XOR sharing into a triple of replicated sharings of that bit.
/// This is not a usable construct, but it can be used with `convert_one_bit` to produce
/// a single replicated sharing of that bit.
///
/// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
///
pub fn convert_bit_local<F: Field>(
    helper_role: Role,
    bit_index: u32,
    input: &XorReplicated,
) -> [Replicated<F>; 3] {
    let left = u128::from(input.left() >> bit_index) & 1;
    let right = u128::from(input.right() >> bit_index) & 1;
    match helper_role {
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
    }
}

pub fn convert_bit_local_list<F: Field>(
    helper_role: Role,
    bit_index: u32,
    input: &[XorReplicated],
) -> Vec<[Replicated<F>; 3]> {
    input
        .iter()
        .map(|v| convert_bit_local::<F>(helper_role, bit_index, v))
        .collect::<Vec<_>>()
}

///
/// Internal use only
/// When both inputs are known to be secret shares of either '1' or '0',
/// XOR can be computed as:
/// a + b - 2*a*b
///
/// This variant is only to be used for the first XOR
/// Where helper 1 has shares:
/// a: (x1, 0) and b: (0, x2)
///
/// And helper 2 has shares:
/// a: (0, 0) and b: (x2, 0)
///
/// And helper 3 has shares:
/// a: (0, x1) and b: (0, 0)
async fn xor_specialized_1<F, C, S>(ctx: C, record_id: RecordId, a: &S, b: &S) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let result = ctx
        .multiply_two_shares_mostly_zeroes(record_id, a, b)
        .await?;

    Ok(-(result * F::from(2)) + a + b)
}

///
/// Internal use only
/// When both inputs are known to be secret share of either '1' or '0',
/// XOR can be computed as:
/// a + b - 2*a*b
///
/// This variant is only to be used for the second XOR
/// Where helper 1 has shares:
/// b: (0, 0)
///
/// And helper 2 has shares:
/// (0, x3)
///
/// And helper 3 has shares:
/// (x3, 0)
async fn xor_specialized_2<F, C, S>(ctx: C, record_id: RecordId, a: &S, b: &S) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let result = ctx
        .multiply_one_share_mostly_zeroes(record_id, a, b)
        .await?;

    Ok(-(result * F::from(2)) + a + b)
}

pub async fn convert_bit<F, C, S>(
    ctx: C,
    record_id: RecordId,
    locally_converted_bits: &[S; 3],
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let (sh0, sh1, sh2) = (
        &locally_converted_bits[0],
        &locally_converted_bits[1],
        &locally_converted_bits[2],
    );
    let ctx1 = ctx.narrow(&Step::Xor1);
    let ctx2 = ctx.narrow(&Step::Xor2);
    let sh0_xor_sh1 = xor_specialized_1(ctx1, record_id, sh0, sh1).await?;
    xor_specialized_2(ctx2, record_id, &sh0_xor_sh1, sh2).await
}

pub async fn convert_bit_list<F, C, S>(
    ctx: C,
    locally_converted_bits: &[[S; 3]],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    try_join_all(
        zip(repeat(ctx), locally_converted_bits.iter())
            .enumerate()
            .map(|(i, (ctx, row))| async move { convert_bit(ctx, RecordId::from(i), row).await }),
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    use crate::ff::{Field, Fp32BitPrime};
    use crate::helpers::{Direction, Role};
    use crate::protocol::context::Context;
    use crate::protocol::malicious::MaliciousValidator;
    use crate::rand::thread_rng;
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::join3;
    use crate::{
        error::Error,
        ff::Fp31,
        protocol::{
            modulus_conversion::{convert_bit, convert_bit_local},
            QueryId, RecordId,
        },
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };
    use proptest::prelude::Rng;

    #[tokio::test]
    pub async fn one_bit() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::new(QueryId);
        let match_key = MaskedMatchKey::mask(rng.gen());
        let result: [Replicated<Fp31>; 3] = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                let triple = convert_bit_local::<Fp31>(ctx.role(), BITNUM, &mk_share);
                convert_bit(ctx, RecordId::from(0), &triple).await.unwrap()
            })
            .await;
        assert_eq!(Fp31::from(match_key.bit(BITNUM)), result.reconstruct());
    }

    #[tokio::test]
    pub async fn one_bit_malicious() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::new(QueryId);
        let match_key = MaskedMatchKey::mask(rng.gen());
        let result: [Replicated<Fp31>; 3] = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                let [x0, x1, x2] = convert_bit_local::<Fp31>(ctx.role(), BITNUM, &mk_share);

                let v = MaliciousValidator::new(ctx);
                let m_triple = join3(
                    v.context().upgrade(RecordId::from(0), x0),
                    v.context().upgrade(RecordId::from(1), x1),
                    v.context().upgrade(RecordId::from(2), x2),
                )
                .await;
                let m_bit = convert_bit(v.context(), RecordId::from(0), &m_triple)
                    .await
                    .unwrap();
                v.validate(m_bit).await.unwrap()
            })
            .await;
        assert_eq!(Fp31::from(match_key.bit(BITNUM)), result.reconstruct());
    }

    #[tokio::test]
    pub async fn one_bit_malicious_tweaks() {
        struct Tweak {
            role: Role,
            value: usize,
            dir: Direction,
        }
        impl Tweak {
            fn flip_bit<F: Field>(
                &self,
                role: Role,
                mut v: [Replicated<F>; 3],
            ) -> [Replicated<F>; 3] {
                if role != self.role {
                    return v;
                }
                let t = &mut v[self.value];
                *t = match self.dir {
                    Direction::Left => Replicated::new(F::ONE - t.left(), t.right()),
                    Direction::Right => Replicated::new(t.left(), F::ONE - t.right()),
                };
                v
            }
        }
        const fn t(role: Role, value: usize, dir: Direction) -> Tweak {
            Tweak { role, value, dir }
        }

        const TWEAKS: &[Tweak] = &[
            t(Role::H1, 0, Direction::Left),
            t(Role::H1, 1, Direction::Right),
            t(Role::H2, 1, Direction::Left),
            t(Role::H2, 2, Direction::Right),
            t(Role::H3, 0, Direction::Right),
            t(Role::H3, 2, Direction::Left),
        ];
        const BITNUM: u32 = 4;

        let mut rng = thread_rng();
        let world = TestWorld::new(QueryId);
        for tweak in TWEAKS {
            let match_key = MaskedMatchKey::mask(rng.gen());
            let _ = world
                .semi_honest(match_key, |ctx, mk_share| async move {
                    let triple = convert_bit_local::<Fp32BitPrime>(ctx.role(), BITNUM, &mk_share);
                    let [x0, x1, x2] = tweak.flip_bit(ctx.role(), triple);

                    let v = MaliciousValidator::new(ctx);
                    let m_ctx = v.context();
                    let m_triple = join3(
                        m_ctx.upgrade(RecordId::from(0), x0),
                        m_ctx.upgrade(RecordId::from(1), x1),
                        m_ctx.upgrade(RecordId::from(2), x2),
                    )
                    .await;
                    let m_bit = convert_bit(m_ctx, RecordId::from(0), &m_triple)
                        .await
                        .unwrap();
                    let err = v.validate(m_bit).await.unwrap_err();
                    assert!(matches!(err, Error::MaliciousSecurityCheckFailed));
                })
                .await;
        }
    }
}
