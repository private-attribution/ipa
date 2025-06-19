use std::{iter::repeat, ops::Not};

use futures::future::{try_join, try_join4, try_join5};

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        BooleanProtocols, RecordId, basics::mul::SecureMul, boolean::step::ThirtyTwoBitStep,
        context::Context,
    },
    secret_sharing::{BitDecomposed, FieldSimd, replicated::semi_honest::AdditiveShare},
};

async fn a_times_b_and_not_b<C, const N: usize>(
    ctx: &C,
    record_id: RecordId,
    a: &AdditiveShare<Boolean, N>,
    b: &AdditiveShare<Boolean, N>,
    step_counter: usize,
) -> Result<(AdditiveShare<Boolean, N>, AdditiveShare<Boolean, N>), Error>
where
    C: Context,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
{
    try_join(
        a.multiply(
            b,
            ctx.narrow(&ThirtyTwoBitStep::from(step_counter)),
            record_id,
        ),
        a.multiply(
            &b.clone().not(),
            ctx.narrow(&ThirtyTwoBitStep::from(step_counter + 1)),
            record_id,
        ),
    )
    .await
}

async fn bit_segments_cross_product<C, const N: usize>(
    ctx: &C,
    record_id: RecordId,
    bit: &AdditiveShare<Boolean, N>,
    segments: &[&AdditiveShare<Boolean, N>],
    step_counter: usize,
) -> Result<Vec<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
{
    ctx.try_join(repeat(bit).zip(segments).enumerate().map(|(i, (b, seg))| {
        let c = ctx.narrow(&ThirtyTwoBitStep::from(step_counter + i));
        async move { b.multiply(seg, c, record_id).await }
    }))
    .await
}

/// Returns an approximate sigmoid function of x
/// Accepts an 8-bit input value, assumed to represent
/// a signed value (two's complement)
/// in Little-Endian format (sign bit is the last bit)
/// Returns an unsigned 8-bit value which should be interpreted
/// as a value between 0 and 1 in Little-Endian format
/// where `0b0000_0000` is 0 and `0b1111_1111` is 255/256
///
/// # Errors
/// propagates errors from multiply
///
/// # Panics
/// If x is not exactly an 8-bit value
pub async fn sigmoid<C, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &BitDecomposed<AdditiveShare<Boolean, N>>,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
{
    assert_eq!(x.len(), 8, "Must provide an 8-bit value");
    let sign_bit_not = x.get(7).unwrap().clone().not();
    let bits = x.iter().map(|b| b + &sign_bit_not).collect::<Vec<_>>();

    let ((seg_1_or_2, seg_3_or_4), (seg_5_or_6, seg_7_or_8)) = try_join(
        a_times_b_and_not_b(&ctx, record_id, &bits[6], &bits[5], 0),
        a_times_b_and_not_b(&ctx, record_id, &bits[6].clone().not(), &bits[5], 2),
    )
    .await?;

    let ((seg_1, seg_2), (seg_3, seg_4), (seg_5, seg_6), seg_7) = try_join4(
        a_times_b_and_not_b(&ctx, record_id, &seg_1_or_2, &bits[4], 4),
        a_times_b_and_not_b(&ctx, record_id, &seg_3_or_4, &bits[4], 6),
        a_times_b_and_not_b(&ctx, record_id, &seg_5_or_6, &bits[4], 8),
        seg_7_or_8.multiply(&bits[4], ctx.narrow(&ThirtyTwoBitStep::from(10)), record_id),
    )
    .await?;

    let segments = [&seg_1, &seg_2, &seg_3, &seg_4, &seg_5, &seg_6];

    let (
        bit_4_and_segments,
        bit_5_and_segments,
        bit_6_and_segments,
        bit_7_and_segments,
        (positive_outside_of_seg_1, positive_outside_of_seg_1_and_2),
    ) = try_join5(
        bit_segments_cross_product(&ctx, record_id, &bits[3], &segments[0..6], 11),
        bit_segments_cross_product(&ctx, record_id, &bits[2], &segments[0..5], 17),
        bit_segments_cross_product(&ctx, record_id, &bits[1], &segments[0..4], 22),
        bit_segments_cross_product(&ctx, record_id, &bits[0], &segments[0..3], 26),
        try_join(
            seg_1.clone().not().multiply(
                &sign_bit_not,
                ctx.narrow(&ThirtyTwoBitStep::from(29)),
                record_id,
            ),
            seg_1_or_2.not().multiply(
                &sign_bit_not,
                ctx.narrow(&ThirtyTwoBitStep::from(30)),
                record_id,
            ),
        ),
    )
    .await?;

    Ok(BitDecomposed::new([
        seg_7
            + positive_outside_of_seg_1_and_2
            + &bit_7_and_segments[2]
            + &bit_6_and_segments[3]
            + &bit_5_and_segments[4]
            + &bit_4_and_segments[5],
        seg_6
            + positive_outside_of_seg_1
            + &bit_7_and_segments[1]
            + &bit_6_and_segments[2]
            + &bit_5_and_segments[3]
            + &bit_4_and_segments[4],
        seg_5
            + &sign_bit_not
            + &bit_7_and_segments[0]
            + &bit_6_and_segments[1]
            + &bit_5_and_segments[2]
            + &bit_4_and_segments[3],
        seg_4
            + &sign_bit_not
            + &bit_6_and_segments[0]
            + &bit_5_and_segments[1]
            + &bit_4_and_segments[2],
        seg_3 + &sign_bit_not + &bit_5_and_segments[0] + &bit_4_and_segments[1],
        seg_2 + &sign_bit_not + &bit_4_and_segments[0],
        seg_1 + &sign_bit_not,
        sign_bit_not,
    ]))
}

#[cfg(all(test, unit_test))]
mod test {
    use std::num::TryFromIntError;

    use crate::{
        ff::{U128Conversions, boolean_array::BA8},
        protocol::{RecordId, context::Context, ipa_prf::boolean_ops::sigmoid::sigmoid},
        secret_sharing::{BitDecomposed, SharedValue, TransposeFrom},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn piecewise_linear_sigmoid_approximation(x: i128) -> Result<u128, TryFromIntError> {
        Ok(match x {
            i128::MIN..=-113 => 0,
            -112..=-97 => 1,
            -96..=-81 => 2 + (u128::try_from(x + 96)? >> 3),
            -80..=-65 => 4 + (u128::try_from(x + 80)? >> 2),
            -64..=-49 => 8 + (u128::try_from(x + 64)? >> 1),
            -48..=-33 => 16 + u128::try_from(x + 48)?,
            -32..=-17 => 32 + (u128::try_from(x + 32)? << 1),
            -16..=15 => 64 + (u128::try_from(x + 16)? << 2),
            16..=31 => 192 + (u128::try_from(x - 16)? << 1),
            32..=47 => 224 + u128::try_from(x - 32)?,
            48..=63 => 240 + (u128::try_from(x - 48)? >> 1),
            64..=79 => 248 + (u128::try_from(x - 64)? >> 2),
            80..=95 => 252 + (u128::try_from(x - 80)? >> 3),
            96..=111 => 254,
            _ => 255,
        })
    }

    fn as_i128(x: BA8) -> i128 {
        let mut out: i128 = i128::try_from(x.as_u128()).unwrap();
        let msb = (out >> (BA8::BITS - 1)) & 1;
        out -= msb * (1 << BA8::BITS);
        out
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn semi_honest_sigmoid() {
        run(|| async move {
            let world = TestWorld::default();

            let all_x_values = (0..256).map(|i| BA8::truncate_from(u128::try_from(i).unwrap()));

            let result: Vec<BA8> = world
                .dzkp_semi_honest(all_x_values, |ctx, all_x_values| async move {
                    let vectorized_inputs = BitDecomposed::transposed_from(&all_x_values).unwrap();

                    let result = sigmoid::<_, 256>(
                        ctx.set_total_records(1),
                        RecordId::FIRST,
                        &vectorized_inputs,
                    )
                    .await
                    .unwrap();

                    Vec::transposed_from(&result).unwrap()
                })
                .await
                .reconstruct();

            for (i, res) in result.iter().enumerate() {
                let u8 = BA8::truncate_from(u128::try_from(i).unwrap());
                let i8 = as_i128(u8);
                let expected = piecewise_linear_sigmoid_approximation(i8).unwrap();

                assert_eq!((i8, res.as_u128()), (i8, expected));

                let x_f64 = (i8 as f64) / 16_f64;
                let y_f64 = (res.as_u128() as f64) / 256_f64;
                let exact_sigmoid = 1.0_f64 / (1.0_f64 + f64::exp(-x_f64));
                let delta_from_exact = f64::abs(exact_sigmoid - y_f64);
                assert!(
                    delta_from_exact < 0.0197_f64,
                    "At x={x_f64} the delta from an exact sigmoid is {delta_from_exact}. Exact value: {exact_sigmoid}, approximate value: {y_f64}"
                );
            }
        });
    }
}
