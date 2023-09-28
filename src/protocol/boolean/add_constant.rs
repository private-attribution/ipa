use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, step::BitOpStep, BasicProtocols, RecordId},
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

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
///
/// # Errors
/// Fails if the multiplication protocol fails.
pub async fn add_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: u128,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
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
        S::share_known_value(&ctx, F::ONE) - &a[0]
    };
    output.push(result_bit);
    let two = F::truncate_from(2_u8);

    for (bit_index, bit) in a.iter().enumerate().skip(1) {
        let mult_result = if last_carry_known_to_be_zero {
            // TODO: this makes me sad
            S::ZERO
                .multiply(&S::ZERO, ctx.narrow(&BitOpStep::from(bit_index)), record_id) // this is stupid
                .await?;

            S::ZERO
        } else {
            last_carry
                .multiply(bit, ctx.narrow(&BitOpStep::from(bit_index)), record_id)
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
            -(&next_carry * two) + &S::share_known_value(&ctx, F::ONE) + bit + &last_carry
        } else {
            -(&next_carry * two) + bit + &last_carry
        };
        output.push(result_bit);

        last_carry = next_carry;
    }
    output.push(last_carry);
    Ok(output)
}

#[cfg(all(test, unit_test))]
mod tests {
    use bitvec::macros::internal::funty::Fundamental;
    use rand::{distributions::Standard, prelude::Distribution};

    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, PrimeField},
        protocol::{boolean::add_constant::add_constant, context::Context, RecordId},
        secret_sharing::{replicated::malicious::ExtendableField, SharedValue},
        test_fixture::{into_bits, Reconstruct, Runner, TestWorld},
    };

    async fn add<F>(world: &TestWorld, a: F, b: u128) -> Vec<F>
    where
        F: PrimeField + ExtendableField,
        Standard: Distribution<F>,
    {
        let input = into_bits(a);
        let result = world
            .semi_honest(input.clone().into_iter(), |ctx, a_share| async move {
                add_constant(ctx.set_total_records(1), RecordId::from(0), &a_share, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .upgraded_malicious(input.into_iter(), |ctx, a_share| async move {
                add_constant(ctx.set_total_records(1), RecordId::from(0), &a_share, b)
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
        let c = Fp31::truncate_from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::default();

        assert_eq!(vec![1, 0, 0, 0, 0, 0], add(&world, zero, 1).await);
        assert_eq!(vec![1, 0, 0, 0, 0, 0], add(&world, one, 0).await);
        assert_eq!(vec![0, 0, 0, 0, 0, 0], add(&world, zero, 0).await);
        assert_eq!(vec![0, 1, 0, 0, 0, 0], add(&world, one, 1).await);

        assert_eq!(vec![0, 1, 0, 1, 0, 0], add(&world, c(3_u8), 7).await);
        assert_eq!(vec![1, 0, 0, 1, 0, 1], add(&world, c(21), 20).await);
        assert_eq!(vec![0, 1, 0, 0, 1, 0], add(&world, c(9), 9).await);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    pub async fn fp32_bit_prime() {
        let zero = Fp32BitPrime::ZERO;
        let world = TestWorld::default();

        // 0 + 0
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ],
            add(&world, zero, 0).await
        );

        // Prime - 1 + 6
        assert_eq!(
            vec![
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1
            ],
            add(
                &world,
                Fp32BitPrime::truncate_from(Fp32BitPrime::PRIME - 1),
                7
            )
            .await
        );

        // 123456789 + 234567890
        assert_eq!(
            vec![
                0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                1, 0, 0, 0, 0
            ],
            add(
                &world,
                Fp32BitPrime::truncate_from(123_456_789_u128),
                234_567_891
            )
            .await
        );

        // some random number (236461931) + (2^l - PRIME)
        let some_random_number = Fp32BitPrime::truncate_from(236_461_931_u128);
        let x: u128 = (1 << 32) - Fp32BitPrime::PRIME.as_u128();
        assert_eq!(
            vec![
                0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                0, 0, 0, 0, 0
            ],
            add(&world, some_random_number, x).await
        );
    }
}
