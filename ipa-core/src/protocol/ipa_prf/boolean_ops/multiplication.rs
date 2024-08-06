use ipa_step::StepNarrow;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        basics::mul::SecureMul, boolean::NBitStep, context::Context,
        ipa_prf::boolean_ops::addition_sequential::integer_add, BooleanProtocols, Gate, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

/// This function multiplies x by y in these steps:
/// 1. Double the input precision for y and repeat the most significant bit in the extra bits (Sign extension)
///    X is assumed to be a positive number, so we will automatically pad with ZERO.
/// 2. Repeatedly multiply x with each digits of y, shift the result 1 digit up each time
/// 3. Add up the partial products using `integer_add`
///    x is assumed to be a positive number
///    y is assumed to be in two's complement and can be either signed or unsigned
#[allow(dead_code)]
pub async fn integer_mul<C, S, const N: usize>(
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
    use super::step::MultiplicationStep as Step;

    let new_len = x.len() + y.len();
    let mut y = y.clone();
    y.resize(new_len, y[y.len() - 1].clone());

    let mut result = BitDecomposed::with_capacity(new_len);
    for (i, yb) in y.into_iter().enumerate() {
        let ctx_for_bit_of_y = ctx.narrow(&S::from(i));
        let product_of_x_and_yb = ctx_for_bit_of_y
            .parallel_join(x.iter().take(new_len - i).enumerate().map(|(j, xb)| {
                let ctx_for_x_times_y_combo = ctx_for_bit_of_y.narrow(&S::from(j));
                let yb = yb.clone();
                async move { yb.multiply(xb, ctx_for_x_times_y_combo, record_id).await }
            }))
            .await?;

        let t = BitDecomposed::try_from(product_of_x_and_yb).unwrap();
        if i == 0 {
            result = t;
        } else {
            // add up bits i.. with the product
            let add_y = BitDecomposed::new(result.clone().into_iter().skip(i));
            let (add_result, carry) = integer_add::<_, S, N>(
                ctx_for_bit_of_y.narrow::<Step>(&Step::Add),
                record_id,
                &t,
                &add_y,
            )
            .await?;

            result = BitDecomposed::new(result.into_iter().take(i).chain(add_result.into_iter()));
            if result.len() < new_len {
                // if carry bit is more than max length, we let it overflow
                result.push(carry);
            }
        }
    }

    Ok(result)
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter;

    use rand::{thread_rng, Rng};

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BooleanArray, BA16, BA8},
            U128Conversions,
        },
        protocol::{
            boolean::step::DefaultBitStep, context::Context,
            ipa_prf::boolean_ops::multiplication::integer_mul, RecordId,
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, TransposeFrom},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn as_i128<B>(x: B) -> i128
    where
        B: BooleanArray + U128Conversions,
    {
        let mut out: i128 = i128::try_from(x.as_u128()).unwrap();
        let msb = (out >> (B::BITS - 1)) & 1;
        out -= msb * (1 << B::BITS);
        out
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn semi_honest_mul() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let all_x_values = (0..256)
                .map(|i| BA8::truncate_from(u128::try_from(i).unwrap()))
                .collect::<Vec<_>>();
            let random_y_values = (0..256).map(|_| rng.gen::<BA8>()).collect::<Vec<_>>();

            let result: Vec<BA16> = world
                .upgraded_semi_honest(
                    all_x_values
                        .clone()
                        .into_iter()
                        .zip(random_y_values.clone()),
                    |ctx, x_y_vals| async move {
                        let (x_vals, y_vals): (Vec<AdditiveShare<BA8>>, Vec<AdditiveShare<BA8>>) =
                            x_y_vals.into_iter().unzip();
                        let mut vectorized_x_inputs: BitDecomposed<AdditiveShare<Boolean, 256>> =
                            BitDecomposed::new(iter::empty());
                        let _ = vectorized_x_inputs.transpose_from(&x_vals);

                        let mut vectorized_y_inputs: BitDecomposed<AdditiveShare<Boolean, 256>> =
                            BitDecomposed::new(iter::empty());
                        let _ = vectorized_y_inputs.transpose_from(&y_vals);

                        let result = integer_mul::<_, DefaultBitStep, 256>(
                            ctx.set_total_records(1),
                            RecordId::FIRST,
                            &vectorized_x_inputs,
                            &vectorized_y_inputs,
                        )
                        .await
                        .unwrap();

                        Vec::transposed_from(&result).unwrap()
                    },
                )
                .await
                .reconstruct();

            for ((res, x), y) in result
                .iter()
                .zip(all_x_values.iter())
                .zip(random_y_values.iter())
            {
                let expected: i128 = as_i128(*y) * i128::try_from(x.as_u128()).unwrap();
                assert_eq!((x, y, expected), (x, y, as_i128(*res)));
            }
        });
    }
}
