use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::Arithmetic as ArithmeticSecretSharing;

/// This is an implementation of a Bitwise Sum of a bitwise-shared number with a constant.
///
/// `BitwiseSum` takes one input: `[a]_B = ([a_0]_p,...,[a_(l-1)]_p)` where
/// `a_0,...,a_(l-1) ∈ {0,1} ⊆ F_p` and a constant value `B`,
/// where only the least significant `l-1` bits of `B` will be used.
///
/// It then computes `[d]_B = ([d_0]_p,...,[d_l]_p)`
/// which is the bit-decomposition of `a + B`.
///
/// Note that the index notation of the inputs is `0..l-1`, whereas the output
/// index notation is `0..l`. This means that the output of this protocol will be
/// "`l+1`"-bit long bitwise secret shares, where `l = |[a]_B|`.
///
/// Really simple logic. Just follows the way you do addition in grade school
/// Starting from the least significant digit add up the digits, carrying when required.
/// We can skip a few multiplications because one input has known values for each bit.
///
/// The tricky part is in computing the "carries".
/// The logic is slightly different for the least significant bit. For that, we just look
/// at the value of the least significant bit of the constant. If it is a zero, then there
/// is no way there is any carry, and the answer is just zero. If it is a one, then the carry
/// will be a one, only if the least significant bit of a `[a_0]_p` is a secret-sharing of one.
/// So it's just equal to `[a_0]_p`.
///
/// For all subsequent carries, once again, it depends on the value of the constant bit at that place:
/// - when the constant has a bit value of zero - there is only a carry if BOTH of the previous carry
/// AND the secret bit are shares of one. We can get this result by just multiplying the two.
///
/// When the constant has a bit value of one - there is a carry if EITHER the previous carry
/// OR the secret bit are shares of one. We can get this result using OR (x OR y = x + y - x*y).
/// So in either case, we need to multiply the previous carry with the next bit of the secret input.
///
/// As such, there are a total of l-2 multiplications (one less than the bit-length of the input).
/// Sometimes, a multiplication can be skipped, because we know, a prioi that the result must be zero.
pub async fn bitwise_add_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: u128,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let mut output = Vec::with_capacity(a.len() + 1);

    let mut last_carry_known_to_be_zero = (b & 1) == 0;
    let mut last_carry = if last_carry_known_to_be_zero {
        S::ZERO
    } else {
        a[0].clone()
    };
    let result_bit = if last_carry_known_to_be_zero {
        a[0].clone()
    } else {
        ctx.share_of_one() - &a[0]
    };
    output.push(result_bit);

    for (bit_index, bit) in a.iter().enumerate().skip(1) {
        let mult_result = if last_carry_known_to_be_zero {
            // TODO: this makes me sad
            let _ = ctx
                .narrow(&BitOpStep::from(bit_index))
                .multiply(record_id, &S::ZERO, &S::ZERO) // this is stupid
                .await?;

            S::ZERO
        } else {
            ctx.narrow(&BitOpStep::from(bit_index))
                .multiply(record_id, &last_carry, bit)
                .await?
        };

        let next_bit_a_one = (b >> bit_index) & 1 == 1;
        let next_carry = if next_bit_a_one {
            last_carry_known_to_be_zero = false;
            -mult_result + &last_carry + bit
        } else {
            mult_result
        };

        let result_bit = if next_bit_a_one {
            -next_carry.clone() * F::from(2) + &ctx.share_of_one() + bit + &last_carry
        } else {
            -next_carry.clone() * F::from(2) + bit + &last_carry
        };
        output.push(result_bit);

        last_carry = next_carry;
    }
    output.push(last_carry);
    Ok(output)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::bitwise_add_constant;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::Runner;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::Context, RecordId},
        test_fixture::{into_bits, Reconstruct, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution};

    async fn add_constant<F: Field>(world: &TestWorld, a: F, b: u128) -> Vec<F>
    where
        Standard: Distribution<F>,
    {
        let input = into_bits(a);
        let result = world
            .semi_honest(input.clone(), |ctx, a_share| async move {
                bitwise_add_constant(ctx.set_total_records(1), RecordId::from(0), &a_share, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious(input, |ctx, a_share| async move {
                bitwise_add_constant(ctx.set_total_records(1), RecordId::from(0), &a_share, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);

        result
    }

    #[tokio::test]
    pub async fn fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::new().await;

        assert_eq!(vec![1, 0, 0, 0, 0, 0], add_constant(&world, zero, 1).await);
        assert_eq!(vec![1, 0, 0, 0, 0, 0], add_constant(&world, one, 0).await);
        assert_eq!(vec![0, 0, 0, 0, 0, 0], add_constant(&world, zero, 0).await);
        assert_eq!(vec![0, 1, 0, 0, 0, 0], add_constant(&world, one, 1).await);

        assert_eq!(
            vec![0, 1, 0, 1, 0, 0],
            add_constant(&world, c(3_u8), 7).await
        );
        assert_eq!(
            vec![1, 0, 0, 1, 0, 1],
            add_constant(&world, c(21), 20).await
        );
        assert_eq!(vec![0, 1, 0, 0, 1, 0], add_constant(&world, c(9), 9).await);
    }

    #[tokio::test]
    pub async fn fp32_bit_prime() {
        let zero = Fp32BitPrime::ZERO;
        let world = TestWorld::new().await;

        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ],
            add_constant(&world, zero, 0).await
        );
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1
            ],
            add_constant(&world, Fp32BitPrime::from(Fp32BitPrime::PRIME - 1), 6).await
        );
        assert_eq!(
            vec![
                1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                1, 0, 0, 0, 0
            ],
            add_constant(&world, Fp32BitPrime::from(123_456_789_u128), 234_567_890).await
        );
    }
}
