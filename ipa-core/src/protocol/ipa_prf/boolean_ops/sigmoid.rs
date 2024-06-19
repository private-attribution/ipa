use std::{iter::repeat, ops::Not};

use futures::future::{try_join, try_join4, try_join5, try_join_all};

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        basics::mul::SecureMul, boolean::step::ThirtyTwoBitStep, context::Context,
        BooleanProtocols, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
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
    try_join_all(repeat(bit).zip(segments).enumerate().map(|(i, (b, seg))| {
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
    use rand::Rng;

    use crate::{
        ff::{boolean_array::BA8, ArrayAccess, I128Conversions},
        protocol::{context::Context, ipa_prf::boolean_ops::sigmoid::sigmoid, RecordId},
        rand::thread_rng,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn piecewise_linear_sigmoid_approximation(x: i128) -> u128 {
        if x < -112 {
            return 0;
        }
        if x < -96 {
            return 1;
        }
        if x < -80 {
            return 2 + (u128::try_from(x + 96).unwrap() >> 3);
        }
        if x < -64 {
            return 4 + (u128::try_from(x + 80).unwrap() >> 2);
        }
        if x < -48 {
            return 8 + (u128::try_from(x + 64).unwrap() >> 1);
        }
        if x < -32 {
            return 16 + u128::try_from(x + 48).unwrap();
        }
        if x < -16 {
            return 32 + 2 * u128::try_from(x + 32).unwrap();
        }
        if x < 16 {
            return 64 + 4 * u128::try_from(x + 16).unwrap();
        }
        if x < 32 {
            return 192 + 2 * u128::try_from(x - 16).unwrap();
        }
        if x < 48 {
            return 224 + u128::try_from(x - 32).unwrap();
        }
        if x < 64 {
            return 240 + (u128::try_from(x - 48).unwrap() >> 1);
        }
        if x < 80 {
            return 248 + (u128::try_from(x - 64).unwrap() >> 2);
        }
        if x < 96 {
            return 252 + (u128::try_from(x - 80).unwrap() >> 3);
        }
        if x < 112 {
            return 254;
        }
        255
    }

    #[test]
    fn semi_honest_sigmoid() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba8 = rng.gen::<BA8>();
            let x = x_ba8.as_i128();

            let expected = piecewise_linear_sigmoid_approximation(x);

            let result = world
                .upgraded_semi_honest(x_ba8, |ctx, x| async move {
                    sigmoid::<_, 1>(ctx.set_total_records(1), RecordId::FIRST, &x.to_bits())
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!((x, result.as_u128()), (x, expected));
        });
    }
}
