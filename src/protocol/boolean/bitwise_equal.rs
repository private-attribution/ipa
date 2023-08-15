use std::iter::zip;

use ipa_macros::step;
use strum::AsRefStr;

use super::xor;
use crate::{
    error::Error,
    ff::{Field, Gf2},
    protocol::{
        basics::SecureMul, boolean::all_zeroes, context::Context, step::BitOpStep, BasicProtocols,
        RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
};

/// Compares `[a]` and `c`, and returns 1 iff `a == c`
///
/// # Errors
/// Propagates errors from multiplications
///
/// # Panics
/// if `a.len() > 128`
pub async fn bitwise_equal_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    c: u128,
) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    assert!(a.len() <= 128);

    let one = S::share_known_value(&ctx, F::ONE);
    // Local XOR
    let xored_bits = a
        .iter()
        .enumerate()
        .map(|(i, a_bit)| {
            if ((c >> i) & 1) == 0 {
                a_bit.clone()
            } else {
                one.clone() - a_bit
            }
        })
        .collect::<Vec<_>>();
    all_zeroes(ctx, record_id, &xored_bits).await
}

///
/// # Errors
/// Propagates errors from multiplications
///
pub async fn bitwise_equal_gf2<C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: &[S],
) -> Result<S, Error>
where
    C: Context,
    S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    debug_assert!(a.len() == b.len());
    let c = zip(a.iter(), b.iter())
        .map(|(a_bit, b_bit)| a_bit.clone() - b_bit)
        .collect::<Vec<_>>();

    all_zeroes(ctx, record_id, &c).await
}

/// # Errors
/// Propagates errors from multiplications
///
pub async fn bitwise_equal<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: &[S],
) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    debug_assert!(a.len() == b.len());
    let xored_bits = xor_all_the_bits(ctx.narrow(&Step::XorAllTheBits), record_id, a, b).await?;
    all_zeroes(ctx, record_id, &xored_bits).await
}

async fn xor_all_the_bits<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: &[S],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
{
    // This is truly a parallel operation across the bits of the input.
    ctx.parallel_join(zip(a, b).enumerate().map(|(i, (a_bit, b_bit))| {
        let c = ctx.narrow(&BitOpStep::from(i));
        async move { xor(c, record_id, a_bit, b_bit).await }
    }))
    .await
}

#[step]
pub(crate) enum Step {
    XorAllTheBits,
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::{bitwise_equal, bitwise_equal_constant};
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::Context, RecordId},
        secret_sharing::BitDecomposed,
        test_fixture::{get_bits, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        assert_eq!(1, run_bitwise_equal(45, 45, 9).await);
        assert_eq!(1, run_bitwise_equal(45, 45, 8).await);
        assert_eq!(1, run_bitwise_equal(45, 45, 7).await);
        assert_eq!(1, run_bitwise_equal(45, 45, 6).await);
        assert_eq!(1, run_bitwise_equal(63, 63, 6).await);
        assert_eq!(1, run_bitwise_equal(63, 63, 3).await);
        assert_eq!(1, run_bitwise_equal(63, 63, 2).await);
        assert_eq!(1, run_bitwise_equal(0, 0, 1).await);
        assert_eq!(1, run_bitwise_equal(u32::MAX, u32::MAX, 32).await);

        assert_eq!(0, run_bitwise_equal(u32::MAX, u32::MAX - 1, 32).await);
        assert_eq!(
            0,
            run_bitwise_equal(u32::MAX, u32::MAX ^ (1 << 15), 32).await
        );
        assert_eq!(0, run_bitwise_equal(0, 1 << 15, 32).await);
        assert_eq!(0, run_bitwise_equal(0, 1, 1).await);
        assert_eq!(0, run_bitwise_equal(0, 1, 2).await);
        assert_eq!(0, run_bitwise_equal(0, 1, 3).await);
        assert_eq!(0, run_bitwise_equal(15, 0, 4).await);
    }

    #[tokio::test]
    pub async fn constant() {
        assert_eq!(1, run_bitwise_equal_constant(45, 45, 9).await);
        assert_eq!(1, run_bitwise_equal_constant(45, 45, 8).await);
        assert_eq!(1, run_bitwise_equal_constant(45, 45, 7).await);
        assert_eq!(1, run_bitwise_equal_constant(45, 45, 6).await);
        assert_eq!(1, run_bitwise_equal_constant(63, 63, 6).await);
        assert_eq!(1, run_bitwise_equal_constant(63, 63, 3).await);
        assert_eq!(1, run_bitwise_equal_constant(63, 63, 2).await);
        assert_eq!(1, run_bitwise_equal_constant(0, 0, 1).await);
        assert_eq!(
            1,
            run_bitwise_equal_constant(u32::MAX, u32::MAX.into(), 32).await
        );

        assert_eq!(
            0,
            run_bitwise_equal_constant(u32::MAX, (u32::MAX - 1).into(), 32).await
        );
        assert_eq!(
            0,
            run_bitwise_equal_constant(u32::MAX, (u32::MAX ^ (1 << 15)).into(), 32).await
        );
        assert_eq!(0, run_bitwise_equal_constant(0, 1 << 15, 32).await);
        assert_eq!(0, run_bitwise_equal_constant(0, 1, 1).await);
        assert_eq!(0, run_bitwise_equal_constant(0, 1, 2).await);
        assert_eq!(0, run_bitwise_equal_constant(0, 1, 3).await);
        assert_eq!(0, run_bitwise_equal_constant(15, 0, 4).await);
    }

    async fn run_bitwise_equal(a: u32, b: u32, num_bits: u32) -> u128 {
        let world = TestWorld::default();

        let a_fp31 = get_bits::<Fp31>(a, num_bits);
        let b_fp31 = get_bits::<Fp31>(b, num_bits);

        let answer_fp31 = world
            .semi_honest(
                (a_fp31, b_fp31),
                |ctx, (a_bits, b_bits): (BitDecomposed<_>, BitDecomposed<_>)| async move {
                    bitwise_equal(
                        ctx.set_total_records(1),
                        RecordId::from(0),
                        &a_bits,
                        &b_bits,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
            .reconstruct();

        let a_fp32_bit_prime = get_bits::<Fp32BitPrime>(a, num_bits);
        let b_fp32_bit_prime = get_bits::<Fp32BitPrime>(b, num_bits);

        let answer_fp32_bit_prime = world
            .semi_honest(
                (a_fp32_bit_prime, b_fp32_bit_prime),
                |ctx, (a_bits, b_bits)| async move {
                    bitwise_equal(
                        ctx.set_total_records(1),
                        RecordId::from(0),
                        &a_bits,
                        &b_bits,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
            .reconstruct();

        assert_eq!(answer_fp31.as_u128(), answer_fp32_bit_prime.as_u128());

        answer_fp31.as_u128()
    }

    async fn run_bitwise_equal_constant(a: u32, b: u128, num_bits: u32) -> u128 {
        let world = TestWorld::default();

        let a_fp31 = get_bits::<Fp31>(a, num_bits);

        let answer_fp31 = world
            .semi_honest(a_fp31, |ctx, a_bits| async move {
                bitwise_equal_constant(ctx.set_total_records(1), RecordId::from(0), &a_bits, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let a_fp32_bit_prime = get_bits::<Fp32BitPrime>(a, num_bits);

        let answer_fp32_bit_prime = world
            .semi_honest(a_fp32_bit_prime, |ctx, a_bits| async move {
                bitwise_equal_constant(ctx.set_total_records(1), RecordId::from(0), &a_bits, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(answer_fp31.as_u128(), answer_fp32_bit_prime.as_u128());

        answer_fp31.as_u128()
    }
}
