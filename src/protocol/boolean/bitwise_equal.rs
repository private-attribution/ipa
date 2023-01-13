use super::xor;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::boolean::no_ones;
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::ArithmeticSecretSharing;
use futures::future::try_join_all;
use std::iter::zip;

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
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    debug_assert!(a.len() == b.len());
    let xored_bits = xor_all_the_bits(ctx.narrow(&Step::XORAllTheBits), record_id, a, b).await?;
    no_ones(ctx, record_id, &xored_bits).await
}

async fn xor_all_the_bits<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: &[S],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let xor = zip(a, b).enumerate().map(|(i, (a_bit, b_bit))| {
        let c = ctx.narrow(&BitOpStep::from(i));
        async move { xor(c, record_id, a_bit, b_bit).await }
    });
    try_join_all(xor).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    XORAllTheBits,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::XORAllTheBits => "xor_all_the_bits",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::test_fixture::Runner;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::RecordId,
        test_fixture::{get_bits, Reconstruct, TestWorld},
    };

    use super::bitwise_equal;

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

    async fn run_bitwise_equal(a: u32, b: u32, num_bits: u32) -> u128 {
        let world = TestWorld::new().await;

        let a_fp31 = get_bits::<Fp31>(a, num_bits);
        let b_fp31 = get_bits::<Fp31>(b, num_bits);

        let answer_fp31 = world
            .semi_honest((a_fp31, b_fp31), |ctx, (a_bits, b_bits)| async move {
                bitwise_equal(ctx, RecordId::from(0), &a_bits, &b_bits)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let a_fp32_bit_prime = get_bits::<Fp32BitPrime>(a, num_bits);
        let b_fp32_bit_prime = get_bits::<Fp32BitPrime>(b, num_bits);

        let answer_fp32_bit_prime = world
            .semi_honest(
                (a_fp32_bit_prime, b_fp32_bit_prime),
                |ctx, (a_bits, b_bits)| async move {
                    bitwise_equal(ctx, RecordId::from(0), &a_bits, &b_bits)
                        .await
                        .unwrap()
                },
            )
            .await
            .reconstruct();

        assert_eq!(answer_fp31.as_u128(), answer_fp32_bit_prime.as_u128());

        answer_fp31.as_u128()
    }
}
