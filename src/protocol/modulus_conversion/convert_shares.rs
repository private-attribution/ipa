use super::specialized_mul::{multiply_one_share_mostly_zeroes, multiply_two_shares_mostly_zeroes};
use crate::{
    error::Error,
    ff::{BinaryField, Field},
    helpers::Role,
    protocol::{context::Context, RecordId},
    secret_sharing::{Replicated, XorReplicated},
};

use crate::protocol::context::SemiHonestContext;
use futures::future::try_join_all;
use std::iter::{repeat, zip};

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

/// Internal use only.
/// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
///
fn local_secret_share<B: BinaryField, F: Field>(
    input: &Replicated<B>,
    helper_role: Role,
) -> [Replicated<F>; 3] {
    let (left, right) = input.as_tuple();
    match helper_role {
        Role::H1 => [
            Replicated::new(F::from(left.as_u128()), F::ZERO),
            Replicated::new(F::ZERO, F::from(right.as_u128())),
            Replicated::new(F::ZERO, F::ZERO),
        ],
        Role::H2 => [
            Replicated::new(F::ZERO, F::ZERO),
            Replicated::new(F::from(left.as_u128()), F::ZERO),
            Replicated::new(F::ZERO, F::from(right.as_u128())),
        ],
        Role::H3 => [
            Replicated::new(F::ZERO, F::from(right.as_u128())),
            Replicated::new(F::ZERO, F::ZERO),
            Replicated::new(F::from(left.as_u128()), F::ZERO),
        ],
    }
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
async fn xor_specialized_1<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error> {
    let result = multiply_two_shares_mostly_zeroes(ctx, record_id, a, b).await?;

    Ok(a + b - &(result * F::from(2)))
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
async fn xor_specialized_2<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error> {
    let result = multiply_one_share_mostly_zeroes(ctx, record_id, a, b).await?;

    Ok(a + b - &(result * F::from(2)))
}

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
pub async fn convert_one_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    input: &XorReplicated,
    bit_index: u32,
) -> Result<Replicated<F>, Error> {
    let [sh0, sh1, sh2] = local_secret_share(&input.bit(bit_index), ctx.role());

    let sh0_xor_sh1 = xor_specialized_1(ctx.narrow(&Step::Xor1), record_id, &sh0, &sh1).await?;
    xor_specialized_2(ctx.narrow(&Step::Xor2), record_id, &sh0_xor_sh1, &sh2).await
}

/// For a given vector of input shares, this returns a vector of modulus converted replicated shares of
/// `bit_index` of each input.
pub async fn convert_shares_for_a_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[XorReplicated],
    num_bits: u32,
    bit_index: u32,
) -> Result<Vec<Replicated<F>>, Error> {
    debug_assert!(num_bits > bit_index);
    let converted_shares = try_join_all(zip(repeat(ctx), input).enumerate().map(
        |(record_id, (ctx, row))| async move {
            let record_id = RecordId::from(record_id);
            convert_one_bit(ctx, record_id, row, bit_index).await
        },
    ))
    .await?;
    Ok(converted_shares)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    use crate::rand::thread_rng;
    use crate::{
        ff::Fp31,
        protocol::{modulus_conversion::convert_one_bit, QueryId, RecordId},
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };
    use proptest::prelude::Rng;

    #[tokio::test]
    pub async fn one_bit() {
        const BITNUM: u32 = 4;
        let mut rng = thread_rng();

        let world = TestWorld::<Fp31>::new(QueryId);
        let match_key = MaskedMatchKey::mask(rng.gen());
        let result = world
            .semi_honest(match_key, |ctx, mk_share| async move {
                convert_one_bit(ctx, RecordId::from(0), &mk_share, BITNUM)
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(Fp31::from(match_key.bit(BITNUM)), result.reconstruct());
    }
}
