use std::{
    iter::{repeat, zip},
    ops::Not,
};

use futures::{
    future::{try_join, try_join4, try_join5},
    stream, StreamExt,
};

use super::multiplication::integer_mul;
use crate::{
    error::{Error, LengthError},
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA8},
    },
    helpers::{repeat_n, TotalRecords},
    protocol::{
        basics::mul::SecureMul,
        boolean::{step::ThirtyTwoBitStep, NBitStep},
        context::Context,
        ipa_prf::aggregation::aggregate_values,
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd, TransposeFrom,
    },
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

// edge_weights[0] holds all the edge weights coming _out_ from the first neuron in the previous layer
pub async fn one_layer<C, S, I, const N: usize>(
    ctx: C,
    last_layer_neurons: Vec<AdditiveShare<BA8>>,
    edge_weights: I,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    S: NBitStep,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
    I: IntoIterator<Item = BitDecomposed<AdditiveShare<Boolean, N>>>,
    BitDecomposed<AdditiveShare<Boolean, N>>:
        for<'a> TransposeFrom<&'a Vec<AdditiveShare<BA8>>, Error = LengthError>,
{
    let multiplication_ctx = ctx.narrow("activation_times_edge_weight");

    let contributions_per_neuron_in_last_layer: Vec<BitDecomposed<AdditiveShare<Boolean, N>>> = ctx
        .parallel_join(zip(edge_weights, last_layer_neurons).enumerate().map(
            |(i, (outbound_edge_weights, last_layer_neuron))| {
                let repeated_neuron_activation = BitDecomposed::transposed_from(
                    &repeat_n(last_layer_neuron, N).collect::<Vec<_>>(),
                )
                .unwrap();
                let c = multiplication_ctx.clone();
                async move {
                    let lossless_result = integer_mul::<_, S, N>(
                        c,
                        RecordId::from(i),
                        &repeated_neuron_activation,
                        &outbound_edge_weights,
                    )
                    .await?;
                    // Neuron activtion is an 8-bit value meant to represent a
                    // fractional number in the range [0, 1)
                    // So after multiplying this value with the edge weight,
                    // we must shift 8 bits down to effectively divide by 256
                    let (_, top_8_bits) = lossless_result.split_at(8);
                    Ok::<_, Error>(top_8_bits)
                }
            },
        ))
        .await?;

    let total_input = aggregate_values::<_, BA16, N>(
        ctx.narrow("aggregated_edge_weights"),
        Box::pin(stream::iter(contributions_per_neuron_in_last_layer.into_iter()).map(Ok)),
        N,
    )
    .await?;

    let (lower_8_bits, _) = total_input.split_at(8);

    sigmoid::<_, N>(
        ctx.narrow("sigmoid")
            .set_total_records(TotalRecords::Indeterminate),
        RecordId::FIRST,
        &lower_8_bits,
    )
    .await
}

#[cfg(all(test, unit_test))]
mod test {
    use std::{iter::zip, num::TryFromIntError};

    use rand::{thread_rng, Rng};

    use super::one_layer;
    use crate::{
        ff::{boolean_array::BA8, U128Conversions},
        protocol::{
            boolean::step::DefaultBitStep, context::Context,
            ipa_prf::boolean_ops::sigmoid::sigmoid, RecordId,
        },
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
                .upgraded_semi_honest(all_x_values, |ctx, all_x_values| async move {
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
                assert!(delta_from_exact < 0.0197_f64, "At x={x_f64} the delta from an exact sigmoid is {delta_from_exact}. Exact value: {exact_sigmoid}, approximate value: {y_f64}");
            }
        });
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn semi_honest_neural_network() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let edge_weights_matrix = (0..32)
                .map(|i| {
                    (0..32).map(|j| {
                        // offset is in the range [-32, 32)
                        let offset = (3 * i + 5 * j) % 64 - 32;
                        let modulo = (256 + offset) % 256;
                        BA8::truncate_from(modulo as u128)
                    }).collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let prev_neurons = (0..32).map(|_| rng.gen::<BA8>()).collect::<Vec<_>>();

            let result: Vec<BA8> = world
                .upgraded_semi_honest(
                    (
                        edge_weights_matrix
                            .clone()
                            .into_iter()
                            .map(|x| x.into_iter()),
                        prev_neurons.clone().into_iter(),
                    ),
                    |ctx, (edge_weights, prev_neurons)| async move {
                        let matrix_of_edge_weights = edge_weights
                            .iter()
                            .map(|chunk| BitDecomposed::transposed_from(chunk).unwrap());
                        let result = one_layer::<_, DefaultBitStep, _, 32>(
                            ctx.set_total_records(32),
                            prev_neurons,
                            matrix_of_edge_weights,
                        )
                        .await
                        .unwrap();

                        Vec::transposed_from(&result).unwrap()
                    },
                )
                .await
                .reconstruct();

            let expected_activations = zip(edge_weights_matrix, prev_neurons)
                .fold([0; 32], |mut acc, (edge_weights, n)| {
                    let contributions_from_neuron = edge_weights.into_iter().map(|e| {
                        let lossless = as_i128(e) * i128::try_from(n.as_u128()).unwrap();
                        lossless >> 8
                    });

                    acc.iter_mut()
                        .zip(contributions_from_neuron)
                        .for_each(|(a, c)| *a += c);
                    acc
                })
                .map(|total_input| {
                    (
                        total_input,
                        piecewise_linear_sigmoid_approximation(total_input).unwrap(),
                    )
                });

            for ((total_input, expected_activation), actual_result) in
                expected_activations.iter().zip(result)
            {
                println!(
                    "total_input: {:?}, expected_activation: {:?}, actual_result: {:?}",
                    total_input, expected_activation, actual_result
                );
                assert_eq!(actual_result.as_u128(), *expected_activation);
            }
        });
    }
}
