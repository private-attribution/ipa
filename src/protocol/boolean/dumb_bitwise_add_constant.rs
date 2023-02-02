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

        // Each bit of the result can be computed very simply. It's just:
        // the current bit of `a` + the current bit of `b` + the carry from the previous bit `-2*next_carry`
        // Since the current bit of `b` has a known value (either 1 or 0), we either add a `share_of_one`, or nothing.
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

pub async fn bitwise_add_constant_maybe<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: u128,
    maybe: &S,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let mut output = Vec::with_capacity(a.len() + 1);

    let mut last_carry = S::ZERO;
    if (b & 1) == 1 {
        let next_carry = ctx
            .narrow(&BitOpStep::from(0))
            .multiply(record_id, &a[0], maybe)
            .await?;
        output.push(-next_carry.clone() * F::from(2) + &a[0] + maybe);
        last_carry = next_carry;
    } else {
        output.push(a[0].clone());
        // In practice, I don't expect to exercize this path, because bit-decomposition
        // involves (maybe) adding `2^l - PRIME`, which in our case is:
        // `2^32 - 4_294_967_291 = 5`
        // ...so the least significant bit will be a `1`.
        // In fact, for ANY prime number, the least significant bit will ALWAYS be `1`
        // Since all primes are odd (apart from 2).
    }

    let ctx_other = ctx.narrow(&Step::CarryXorBitTimesMaybe);
    for (bit_index, bit) in a.iter().enumerate().skip(1) {
        let next_bit = (b >> bit_index) & 1;
        let carry_times_bit = ctx
            .narrow(&BitOpStep::from(bit_index))
            .multiply(record_id, bit, &last_carry)
            .await?;

        if next_bit == 0 {
            let next_carry = carry_times_bit;

            output.push(-next_carry.clone() * F::from(2) + bit + &last_carry);

            last_carry = next_carry;
        } else {
            let carry_xor_bit = -carry_times_bit.clone() * F::from(2) + &last_carry + bit;

            let carry_xor_bit_times_maybe = ctx_other
                .narrow(&BitOpStep::from(bit_index))
                .multiply(record_id, &carry_xor_bit, maybe)
                .await?;

            let next_carry = carry_xor_bit_times_maybe + &carry_times_bit;

            output.push(-next_carry.clone() * F::from(2) + bit + maybe + &last_carry);

            last_carry = next_carry;
        }
    }
    output.push(last_carry);
    Ok(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    CarryXorBitTimesMaybe,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::CarryXorBitTimesMaybe => "carry_xor_bit_times_maybe",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::bitwise_add_constant;
    use crate::protocol::boolean::dumb_bitwise_add_constant::bitwise_add_constant_maybe;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::Runner;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::Context, RecordId},
        test_fixture::{into_bits, Reconstruct, TestWorld},
    };
    use bitvec::macros::internal::funty::Fundamental;
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

    async fn add_constant_maybe<F: Field>(world: &TestWorld, a: F, b: u128, maybe: F) -> Vec<F>
    where
        Standard: Distribution<F>,
    {
        let input = (into_bits(a), maybe);
        let result = world
            .semi_honest(input.clone(), |ctx, (a_share, maybe_share)| async move {
                bitwise_add_constant_maybe(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    b,
                    &maybe_share,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious(input, |ctx, (a_share, maybe_share)| async move {
                bitwise_add_constant_maybe(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    b,
                    &maybe_share,
                )
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
        assert_eq!(
            vec![1, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, zero, 1, one).await
        );
        assert_eq!(
            vec![0, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, zero, 1, zero).await
        );
        assert_eq!(vec![1, 0, 0, 0, 0, 0], add_constant(&world, one, 0).await);
        assert_eq!(
            vec![1, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, one, 0, one).await
        );
        assert_eq!(
            vec![1, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, one, 0, zero).await
        );
        assert_eq!(vec![0, 0, 0, 0, 0, 0], add_constant(&world, zero, 0).await);
        assert_eq!(
            vec![0, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, zero, 0, one).await
        );
        assert_eq!(
            vec![0, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, zero, 0, zero).await
        );
        assert_eq!(vec![0, 1, 0, 0, 0, 0], add_constant(&world, one, 1).await);
        assert_eq!(
            vec![0, 1, 0, 0, 0, 0],
            add_constant_maybe(&world, one, 1, one).await
        );
        assert_eq!(
            vec![1, 0, 0, 0, 0, 0],
            add_constant_maybe(&world, one, 1, zero).await
        );

        assert_eq!(
            vec![0, 1, 0, 1, 0, 0],
            add_constant(&world, c(3_u8), 7).await
        );
        assert_eq!(
            vec![0, 1, 0, 1, 0, 0],
            add_constant_maybe(&world, c(3_u8), 7, one).await
        );
        assert_eq!(
            vec![1, 1, 0, 0, 0, 0],
            add_constant_maybe(&world, c(3_u8), 7, zero).await
        );
        assert_eq!(
            vec![1, 0, 0, 1, 0, 1],
            add_constant(&world, c(21), 20).await
        );
        assert_eq!(vec![0, 1, 0, 0, 1, 0], add_constant(&world, c(9), 9).await);
        assert_eq!(
            vec![0, 1, 0, 0, 1, 0],
            add_constant_maybe(&world, c(9), 9, one).await
        );
        assert_eq!(
            vec![1, 0, 0, 1, 0, 0],
            add_constant_maybe(&world, c(9), 9, zero).await
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    pub async fn fp32_bit_prime() {
        let zero = Fp32BitPrime::ZERO;
        let one = Fp32BitPrime::ONE;
        let world = TestWorld::new().await;

        // 0 + 0
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
                0, 0, 0, 0, 0
            ],
            add_constant_maybe(&world, zero, 0, one).await
        );
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ],
            add_constant_maybe(&world, zero, 0, zero).await
        );

        // Prime - 1 + 6
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1
            ],
            add_constant(&world, Fp32BitPrime::from(Fp32BitPrime::PRIME - 1), 6).await
        );
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1
            ],
            add_constant_maybe(&world, Fp32BitPrime::from(Fp32BitPrime::PRIME - 1), 6, one).await
        );
        assert_eq!(
            vec![
                0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 0
            ],
            add_constant_maybe(&world, Fp32BitPrime::from(Fp32BitPrime::PRIME - 1), 6, zero).await
        );

        // 123456789 + 234567890
        assert_eq!(
            vec![
                1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                1, 0, 0, 0, 0
            ],
            add_constant(&world, Fp32BitPrime::from(123_456_789_u128), 234_567_890).await
        );
        assert_eq!(
            vec![
                1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                1, 0, 0, 0, 0
            ],
            add_constant_maybe(
                &world,
                Fp32BitPrime::from(123_456_789_u128),
                234_567_890,
                one
            )
            .await
        );
        assert_eq!(
            vec![
                1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0,
                0, 0, 0, 0, 0
            ],
            add_constant_maybe(
                &world,
                Fp32BitPrime::from(123_456_789_u128),
                234_567_890,
                zero
            )
            .await
        );

        // some random number (236461931) + (2^l - PRIME)
        let some_random_number = Fp32BitPrime::from(236_461_931_u128);
        let x: u128 = (1 << 32) - Fp32BitPrime::PRIME.as_u128();
        assert_eq!(
            vec![
                0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                0, 0, 0, 0, 0
            ],
            add_constant(&world, some_random_number, x).await
        );
        assert_eq!(
            vec![
                0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                0, 0, 0, 0, 0
            ],
            add_constant_maybe(&world, some_random_number, x, one).await
        );
        assert_eq!(
            vec![
                1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                0, 0, 0, 0, 0
            ],
            add_constant_maybe(&world, some_random_number, x, zero).await
        );
    }
}
