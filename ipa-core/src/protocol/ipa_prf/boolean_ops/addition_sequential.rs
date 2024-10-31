use std::iter::{repeat, repeat_n};

use ipa_step::StepNarrow;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        basics::{BooleanProtocols, SecureMul},
        boolean::{or::bool_or, NBitStep},
        context::Context,
        Gate, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

/// Non-saturated unsigned integer addition
/// This function adds y to x.
/// The output has same length as x.
/// Indices of y beyond the length of x are ignored, but
/// the final carry is returned
///
/// # Errors
/// propagates errors from multiply
pub async fn integer_add<C, S, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &BitDecomposed<AdditiveShare<Boolean, N>>,
    y: &BitDecomposed<AdditiveShare<Boolean, N>>,
) -> Result<
    (
        BitDecomposed<AdditiveShare<Boolean, N>>,
        AdditiveShare<Boolean, N>,
    ),
    Error,
>
where
    C: Context,
    S: NBitStep,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
    Gate: StepNarrow<S>,
{
    let mut carry = AdditiveShare::ZERO;
    let sum = addition_circuit::<_, S, N>(ctx, record_id, x, y, &mut carry).await?;
    Ok((sum, carry))
}

/// saturated unsigned integer addition
/// currently not used, but it is tested
/// adds y to x, Output has same length as x (we dont seem to need support for different length)
/// # Errors
/// propagates errors from multiply
pub async fn integer_sat_add<C, S, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &BitDecomposed<AdditiveShare<Boolean, N>>,
    y: &BitDecomposed<AdditiveShare<Boolean, N>>,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    S: NBitStep,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
    Gate: StepNarrow<S>,
{
    use super::step::SaturatedAdditionStep as Step;

    let mut carry = AdditiveShare::<Boolean, N>::ZERO;
    let result =
        addition_circuit::<_, S, N>(ctx.narrow::<Step>(&Step::Add), record_id, x, y, &mut carry)
            .await?;

    // if carry==1 then {all ones} else {result}
    bool_or::<_, S, _, N>(
        ctx.narrow::<Step>(&Step::Select),
        record_id,
        &result,
        repeat_n(&carry, x.len()),
    )
    .await
}

/// addition using bit adder
/// adds y to x, Output has same length as x (carries and indices of y too large for x are ignored)
/// implementing `https://encrypto.de/papers/KSS09.pdf` from Section 3.1
/// for all i: output[i] = x[i] + (c[i-1] + y[i])
/// # Errors
/// propagates errors from multiply
///
///
async fn addition_circuit<C, S, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &BitDecomposed<AdditiveShare<Boolean, N>>,
    y: &BitDecomposed<AdditiveShare<Boolean, N>>,
    carry: &mut AdditiveShare<Boolean, N>,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    S: NBitStep,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
    Gate: StepNarrow<S>,
{
    let x = x.iter();
    let y = y.iter();

    let mut result = BitDecomposed::with_capacity(x.len());
    for (i, (xb, yb)) in x.zip(y.chain(repeat(&AdditiveShare::ZERO))).enumerate() {
        result.push(bit_adder(ctx.narrow(&S::from(i)), record_id, xb, yb, carry).await?);
    }
    Ok(result)
}

///
/// This one-bit adder that only requires a single multiplication was taken from:
/// "Improved Garbled Circuit Building Blocks and Applications to Auctions and Computing Minima"
/// `https://encrypto.de/papers/KSS09.pdf`
///
/// Section 3.1 Integer Addition, Subtraction and Multiplication
///
/// For each bit, the `sum_bit` can be efficiently computed as just `s_i = x_i ⊕ y_i ⊕ c_i`
/// This can be computed "for free" in Gf2
///
/// The `carry_out` bit can be efficiently computed with just a single multiplication as:
/// `c_(i+1) = c_i ⊕ ((x_i ⊕ c_i) & (y_i ⊕ c_i))`
///
/// Returns `sum_bit`
///
/// The mutable refernce to `carry` is mutated to take on the value of the `carry_out` bit
///
/// # Errors
/// propagates errors from multiply
async fn bit_adder<C, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<Boolean, N>,
    y: &AdditiveShare<Boolean, N>,
    carry: &mut AdditiveShare<Boolean, N>,
) -> Result<AdditiveShare<Boolean, N>, Error>
where
    C: Context,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
{
    let output = x + y + &*carry;

    *carry = &*carry
        + (x + &*carry)
            .multiply(&(y + &*carry), ctx, record_id)
            .await?;

    Ok(output)
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;

    use crate::{
        ff::{
            boolean_array::{BA16, BA32, BA64},
            ArrayAccess, U128Conversions,
        },
        protocol::{
            boolean::step::DefaultBitStep,
            context::Context,
            ipa_prf::boolean_ops::addition_sequential::{integer_add, integer_sat_add},
            RecordId,
        },
        rand::thread_rng,
        secret_sharing::BitDecomposed,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    /// testing correctness of addition
    #[test]
    fn semi_honest_add() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba64 = rng.gen::<BA64>();
            let y_ba64 = rng.gen::<BA64>();
            let x = x_ba64.as_u128();
            let y = y_ba64.as_u128();

            let expected = (x + y) % (1 << 64);
            let expected_carry = (x + y) >> 64 & 1;

            let (result, carry) = world
                .dzkp_semi_honest((x_ba64, y_ba64), |ctx, x_y| async move {
                    integer_add::<_, DefaultBitStep, 1>(
                        ctx.set_total_records(1),
                        RecordId::FIRST,
                        &x_y.0.to_bits(),
                        &x_y.1.to_bits(),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(
                (x, y, result.as_u128(), carry.as_u128()),
                (x, y, expected, expected_carry)
            );
        });
    }

    #[test]
    fn semi_honest_sat_add() {
        run(|| async move {
            const BITS: usize = 16;
            type BA = BA16;

            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba = rng.gen::<BA>();
            let y_ba = rng.gen::<BA>();
            let x = x_ba.as_u128();
            let y = y_ba.as_u128();
            let z = 1_u128 << BITS;

            let x_bits = BitDecomposed::new(x_ba);
            let y_bits = BitDecomposed::new(y_ba);

            let expected = if x + y > z { z - 1 } else { (x + y) % z };

            let result = world
                .dzkp_semi_honest((x_bits, y_bits), |ctx, x_y| async move {
                    integer_sat_add::<_, DefaultBitStep, 1>(
                        ctx.set_total_records(1),
                        RecordId::FIRST,
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .into_iter()
                .enumerate()
                .fold(0, |acc, (i, b)| acc + b.as_u128() * (1 << i));

            assert_eq!((x, y, z, result), (x, y, z, expected));
        });
    }

    #[test]
    fn semi_honest_add_differing_lengths() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba64 = rng.gen::<BA64>();
            let y_ba32 = rng.gen::<BA32>();
            let x = x_ba64.as_u128();
            let y = y_ba32.as_u128();

            let expected = (x + y) % (1 << 64);
            let expected_carry = (x + y) >> 64 & 1;

            let (result, carry) = world
                .dzkp_semi_honest((x_ba64, y_ba32), |ctx, x_y| async move {
                    integer_add::<_, DefaultBitStep, 1>(
                        ctx.set_total_records(1),
                        RecordId::FIRST,
                        &x_y.0.to_bits(),
                        &x_y.1.to_bits(),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(
                (x, y, result.as_u128(), carry.as_u128()),
                (x, y, expected, expected_carry)
            );

            let x = x & ((1 << 32) - 1);
            let expected = (x + y) % (1 << 32);
            let expected_carry = (x + y) >> 32 & 1;
            let (result, carry) = world
                .dzkp_semi_honest((y_ba32, x_ba64), |ctx, x_y| async move {
                    integer_add::<_, DefaultBitStep, 1>(
                        ctx.set_total_records(1),
                        RecordId::FIRST,
                        &x_y.0.to_bits(),
                        &x_y.1.to_bits(),
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(
                (x, y, result.as_u128(), carry.as_u128()),
                (x, y, expected, expected_carry)
            );
        });
    }
}
