// DP in MPC
pub mod step;
use std::f64;

use futures_util::{stream, StreamExt};

use crate::{
    error::{Error, LengthError},
    ff::{boolean::Boolean, boolean_array::BooleanArray, U128Conversions},
    helpers::TotalRecords,
    protocol::{
        boolean::step::SixteenBitStep,
        context::Context,
        dp::step::DPStep,
        ipa_prf::{aggregation::aggregate_values, boolean_ops::addition_sequential::integer_add},
        prss::{FromPrss, SharedRandomness},
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::{AdditiveShare as Replicated, AdditiveShare},
        BitDecomposed, FieldSimd, TransposeFrom, Vectorizable,
    },
};
/// # Panics
/// Will panic if there are not enough bits in the outputs size for the noise gen sum. We can't have the noise sum saturate
/// as that would be insecure noise.
/// # Errors
/// may have errors generated in `aggregate_values` also some asserts here
pub async fn gen_binomial_noise<C, const B: usize, OV>(
    ctx: C,
    num_bernoulli: u32,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    C: Context,
    Boolean: Vectorizable<B> + FieldSimd<B>,
    BitDecomposed<Replicated<Boolean, B>>: FromPrss<usize>,
    OV: BooleanArray + U128Conversions,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
{
    // Step 1:  Generate Bernoulli's with PRSS
    // sample a stream of `total_bits = num_bernoulli * B` bit from PRSS where B is number of histogram bins
    // and num_bernoulli is the number of Bernoulli samples to sum to get a sample from a Binomial
    // distribution with the desired epsilon, delta
    // To ensure that the output value has enough bits to hold the sum without saturating (which would be insecure noise),
    // add an assert about log_2(num_histogram_bins) < OV:BITS to make sure enough space in OV for sum
    assert!(
        num_bernoulli.ilog2() < OV::BITS,
        "not enough bits in output size for noise gen sum"
    );
    let bits = 1;
    let mut vector_input_to_agg: Vec<_> = vec![];
    for i in 0..num_bernoulli {
        let element: BitDecomposed<Replicated<Boolean, B>> =
            ctx.prss().generate_with(RecordId::from(i), bits);
        vector_input_to_agg.push(element);
    }
    // Step 2: Convert to input from needed for aggregate_values
    let aggregation_input = Box::pin(stream::iter(vector_input_to_agg.into_iter()).map(Ok));
    // Step 3: Call `aggregate_values` to sum up Bernoulli noise.
    let noise_vector: Result<BitDecomposed<AdditiveShare<Boolean, { B }>>, Error> =
        aggregate_values::<_, OV, B>(ctx, aggregation_input, num_bernoulli as usize).await;
    noise_vector
}
/// `apply_dp_noise` takes the noise distribution parameters (`num_bernoulli` and in the future `quantization_scale`)
/// and the vector of values to have noise added to.
/// It calls `gen_binomial_noise` to create the noise in MPC and applies it
/// # Panics
/// asserts that `num_histogram_bins` matches what we are using for vectorization, B.
/// # Errors
/// Result error case could come from transpose
pub async fn apply_dp_noise<C, const B: usize, OV>(
    ctx: C,
    histogram_bin_values: BitDecomposed<Replicated<Boolean, B>>,
    num_bernoulli: u32,
) -> Result<Vec<Replicated<OV>>, Error>
where
    C: Context,
    Boolean: Vectorizable<B> + FieldSimd<B>,
    BitDecomposed<Replicated<Boolean, B>>: FromPrss<usize>,
    OV: BooleanArray + U128Conversions,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    Vec<Replicated<OV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    let noise_gen_ctx = ctx.narrow(&DPStep::NoiseGen);
    let noise_vector = gen_binomial_noise::<C, B, OV>(noise_gen_ctx, num_bernoulli)
        .await
        .unwrap();
    // Step 4:  Add DP noise to output values
    let apply_noise_ctx = ctx
        .narrow(&DPStep::ApplyNoise)
        .set_total_records(TotalRecords::ONE);
    let (histogram_noised, _) = integer_add::<_, SixteenBitStep, B>(
        apply_noise_ctx,
        RecordId::FIRST,
        &noise_vector,
        &histogram_bin_values,
    )
    .await
    .unwrap();
    // Step 5 Transpose output representation
    Ok(Vec::transposed_from(&histogram_noised)?)
}
// implement calculations to instantiation Thm 1 of https://arxiv.org/pdf/1805.10559
// which lets us determine the minimum necessary num_bernoulli for a given epsilon, delta
// and other parameters
// translation of notation from the paper to Rust variable names:
//     p = success_prob
//     s = quantization_scale
//     Delta_1 = ell_1_sensitivity
//     Delta_2 = ell_2_sensitivity
//     Delta_infty = ell_infty_sensitivity
//     N = num_bernoulli
//     d = dimensions
/// equation (17)
#[allow(dead_code)]
fn b_p(success_prob: f64) -> f64 {
    (2.0 / 3.0) * (success_prob.powi(2) + (1.0 - success_prob).powi(2)) + 1.0 - 2.0 * success_prob
}
/// equation (12)
#[allow(dead_code)]
fn c_p(success_prob: f64) -> f64 {
    2.0_f64.sqrt()
        * (3.0 * success_prob.powi(3)
            + 3.0 * (1.0 - success_prob).powi(3)
            + 2.0 * success_prob.powi(2)
            + 2.0 * (1.0 - success_prob).powi(2))
}
/// equation (16)
#[allow(dead_code)]
fn d_p(success_prob: f64) -> f64 {
    (4.0 / 3.0) * (success_prob.powi(2) + (1.0 - success_prob).powi(2))
}
/// equation (7)
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn epsilon_constraint(
    num_bernoulli: u32,
    success_prob: f64,
    delta: f64,
    quantization_scale: f64,
    dimensions: f64,
    ell_1_sensitivity: f64,
    ell_2_sensitivity: f64,
    ell_infty_sensitivity: f64,
) -> f64 {
    let num_bernoulli_f64 = f64::from(num_bernoulli);
    let first_term_num = ell_2_sensitivity * (2.0 * (1.25 / delta).ln()).sqrt();
    let first_term_den =
        quantization_scale * (num_bernoulli_f64 * success_prob * (1.0 - success_prob)).sqrt();
    let second_term_num = ell_2_sensitivity * c_p(success_prob) * ((10.0 / delta).ln()).sqrt()
        + ell_1_sensitivity * b_p(success_prob);
    let second_term_den = quantization_scale
        * num_bernoulli_f64
        * success_prob
        * (1.0 - success_prob)
        * (1.0 - delta / 10.0);
    let third_term_num = (2.0 / 3.0) * ell_infty_sensitivity * (1.25 / delta).ln()
        + ell_infty_sensitivity
            * d_p(success_prob)
            * (20.0 * dimensions / delta).ln()
            * (10.0 / delta).ln();
    let third_term_den =
        quantization_scale * num_bernoulli_f64 * success_prob * (1.0 - success_prob);
    first_term_num / first_term_den
        + second_term_num / second_term_den
        + third_term_num / third_term_den
}
/// constraint from delta in Thm 1
#[allow(dead_code)]
fn delta_constraint(
    num_bernoulli: u32,
    success_prob: f64,
    dimensions: f64,
    quantization_scale: f64,
    delta: f64,
    ell_infty_sensitivity: f64,
) -> bool {
    let lhs = f64::from(num_bernoulli) * success_prob * (1.0 - success_prob);
    let rhs = (23.0 * (10.0 * dimensions / delta).ln())
        .max(2.0 * ell_infty_sensitivity / quantization_scale);
    lhs >= rhs
}
/// error of mechanism in Thm 1
#[allow(dead_code)]
fn error(num_bernoulli: u32, success_prob: f64, dimensions: f64, quantization_scale: f64) -> f64 {
    dimensions
        * quantization_scale.powi(2)
        * f64::from(num_bernoulli)
        * success_prob
        * (1.0 - success_prob)
}
/// for fixed p (and other params), find smallest `num_bernoulli` such that `epsilon < desired_epsilon`
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn find_smallest_num_bernoulli(
    desired_epsilon: f64,
    success_prob: f64,
    delta: f64,
    dimensions: f64,
    quantization_scale: f64,
    ell_1_sensitivity: f64,
    ell_2_sensitivity: f64,
    ell_infty_sensitivity: f64,
) -> u32 {
    let mut index = 0; // candidate to be smallest `num_beroulli`
    let mut lower: u32 = 1;
    let mut higher: u32 = 10_000_000;
    // binary search to find smallest `num_beroulli`. Binary search
    // like the improved version of template #2 found in this article
    // https://medium.com/@berkkantkoc/a-handy-binary-search-template-that-will-save-you-6b36b7b06b8b
    while lower <= higher {
        let mid: u32 = (higher - lower) / 2 + lower;
        if delta_constraint(
            mid,
            success_prob,
            dimensions,
            quantization_scale,
            delta,
            ell_infty_sensitivity,
        ) && desired_epsilon
            >= epsilon_constraint(
                mid,
                success_prob,
                delta,
                quantization_scale,
                dimensions,
                ell_1_sensitivity,
                ell_2_sensitivity,
                ell_infty_sensitivity,
            )
        {
            index = mid;
            higher = mid - 1;
        } else {
            lower = mid + 1;
        }
    }
    assert!(index > 0, "smallest num_bernoulli not found");
    index
}
#[cfg(all(test, unit_test))]
mod test {
    use crate::{
        ff::{boolean::Boolean, boolean_array::BA16, U128Conversions},
        protocol::dp::{
            apply_dp_noise, delta_constraint, epsilon_constraint, error,
            find_smallest_num_bernoulli, gen_binomial_noise,
        },
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, TransposeFrom,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    #[test]
    fn test_epsilon_simple_aggregation_case() {
        let delta = 1e-6;
        let dimensions = 1.0;
        let quantization_scale = 1.0;
        let success_prob = 0.5;
        let ell_1_sensitivity = 1.0;
        let ell_2_sensitivity = 1.0;
        let ell_infty_sensitivity = 1.0;
        let num_bernoulli = 2000;
        assert!(delta_constraint(
            num_bernoulli,
            success_prob,
            dimensions,
            quantization_scale,
            delta,
            ell_infty_sensitivity
        ));
        let eps = epsilon_constraint(
            num_bernoulli,
            success_prob,
            delta,
            quantization_scale,
            dimensions,
            ell_1_sensitivity,
            ell_2_sensitivity,
            ell_infty_sensitivity,
        );
        assert!(eps > 0.6375 && eps < 0.6376, "eps = {eps}");
    }
    #[test]
    fn test_num_bernoulli_simple_aggregation_case() {
        // test with success_prob = 1/2
        let mut success_prob = 0.5;
        let desired_epsilon = 1.0;
        let delta = 1e-6;
        let dimensions = 1.0;
        let quantization_scale = 1.0;
        let ell_1_sensitivity = 1.0;
        let ell_2_sensitivity = 1.0;
        let ell_infty_sensitivity = 1.0;
        let mut smallest_num_bernoulli = find_smallest_num_bernoulli(
            desired_epsilon,
            success_prob,
            delta,
            dimensions,
            quantization_scale,
            ell_1_sensitivity,
            ell_2_sensitivity,
            ell_infty_sensitivity,
        );
        let err = error(
            smallest_num_bernoulli,
            success_prob,
            dimensions,
            quantization_scale,
        );
        assert_eq!(smallest_num_bernoulli, 1483_u32);
        assert!(err <= 370.75 && err > 370.7);

        // test with success_prob = 1/4
        success_prob = 0.25;
        smallest_num_bernoulli = find_smallest_num_bernoulli(
            desired_epsilon,
            success_prob,
            delta,
            dimensions,
            quantization_scale,
            ell_1_sensitivity,
            ell_2_sensitivity,
            ell_infty_sensitivity,
        );
        assert_eq!(smallest_num_bernoulli, 1978_u32);

        // test with success_prob = 3/4
        success_prob = 0.75;
        smallest_num_bernoulli = find_smallest_num_bernoulli(
            desired_epsilon,
            success_prob,
            delta,
            dimensions,
            quantization_scale,
            ell_1_sensitivity,
            ell_2_sensitivity,
            ell_infty_sensitivity,
        );
        assert_eq!(smallest_num_bernoulli, 1978_u32);
    }
    // Tests for apply_dp_noise
    #[tokio::test]
    pub async fn test_apply_dp_noise() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 16;
        let num_bernoulli: u32 = 1000;
        let world = TestWorld::default();
        let input_values = [10, 8, 6, 41, 0, 0, 0, 0, 10, 8, 6, 41, 0, 0, 0, 0];
        let input: BitDecomposed<[Boolean; NUM_BREAKDOWNS as usize]> =
            vectorize_input(16, &input_values);
        let result = world
            .upgraded_semi_honest(input, |ctx, input| async move {
                apply_dp_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                    ctx,
                    input,
                    num_bernoulli,
                )
                .await
                .unwrap()
            })
            .await;
        let result_type_confirm: [Vec<Replicated<OutputValue>>; 3] = result;
        let result_reconstructed: Vec<OutputValue> = result_type_confirm.reconstruct();
        let result_u32: Vec<u32> = result_reconstructed
            .iter()
            .map(|&v| u32::try_from(v.as_u128()).unwrap())
            .collect::<Vec<_>>();
        let mean: f64 = f64::from(num_bernoulli) * 0.5; // n * p
        let standard_deviation: f64 = (f64::from(num_bernoulli) * 0.5 * 0.5).sqrt(); //  sqrt(n * (p) * (1-p))
        assert_eq!(NUM_BREAKDOWNS as usize, result_u32.len());
        for i in 0..result_u32.len() {
            assert!(
                f64::from(result_u32[i]) - f64::from(input_values[i])
                    > mean - 5.0 * standard_deviation
                    && f64::from(result_u32[i]) - f64::from(input_values[i])
                    < mean + 5.0 * standard_deviation
                , "test failed because noised result is more than 5 standard deviations of the noise distribution \
                from the original input values. This will fail with a small chance of failure"
            );
        }
    }
    fn vectorize_input<const B: usize>(
        bit_width: usize,
        values: &[u32],
    ) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();
        BitDecomposed::decompose(bit_width, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }
    // Tests for gen_bernoulli_noise
    #[tokio::test]
    pub async fn test_16_breakdowns() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 16;
        let num_bernoulli: u32 = 10000;
        let world = TestWorld::default();
        let result = world
            .upgraded_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli,
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_type_confirm: [Vec<Replicated<OutputValue>>; 3] = result;
        let result_reconstructed: Vec<OutputValue> = result_type_confirm.reconstruct();
        let result_u32: Vec<u32> = result_reconstructed
            .iter()
            .map(|&v| u32::try_from(v.as_u128()).unwrap())
            .collect::<Vec<_>>();
        let mean: f64 = f64::from(num_bernoulli) * 0.5; // n * p
        let standard_deviation: f64 = (f64::from(num_bernoulli) * 0.5 * 0.5).sqrt(); //  sqrt(n * (p) * (1-p))
        assert_eq!(NUM_BREAKDOWNS as usize, result_u32.len());
        for sample in &result_u32 {
            assert!(
                f64::from(*sample) > mean - 5.0 * standard_deviation
                    && f64::from(*sample) < mean + 5.0 * standard_deviation
            );
        }
        println!("result as u32 {result_u32:?}");
    }
    #[tokio::test]
    pub async fn test_32_breakdowns() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 32;
        let num_bernoulli: u32 = 2000;
        let world = TestWorld::default();
        let result = world
            .upgraded_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli,
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_type_confirm: [Vec<Replicated<OutputValue>>; 3] = result;
        let result_reconstructed: Vec<OutputValue> = result_type_confirm.reconstruct();
        let result_u32: Vec<u32> = result_reconstructed
            .iter()
            .map(|&v| u32::try_from(v.as_u128()).unwrap())
            .collect::<Vec<_>>();
        let mean: f64 = f64::from(num_bernoulli) * 0.5; // n * p
        let standard_deviation: f64 = (f64::from(num_bernoulli) * 0.5 * 0.5).sqrt(); //  sqrt(n * (p) * (1-p))
        assert_eq!(NUM_BREAKDOWNS as usize, result_u32.len());
        for sample in &result_u32 {
            assert!(
                f64::from(*sample) > mean - 5.0 * standard_deviation
                    && f64::from(*sample) < mean + 5.0 * standard_deviation
            );
        }
        println!("result as u32 {result_u32:?}");
    }
    #[tokio::test]
    pub async fn test_256_breakdowns() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 256;
        let num_bernoulli: u32 = 1000;
        let world = TestWorld::default();
        let result = world
            .upgraded_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli,
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_type_confirm: [Vec<Replicated<OutputValue>>; 3] = result;
        let result_reconstructed: Vec<OutputValue> = result_type_confirm.reconstruct();
        let result_u32: Vec<u32> = result_reconstructed
            .iter()
            .map(|&v| u32::try_from(v.as_u128()).unwrap())
            .collect::<Vec<_>>();
        let mean: f64 = f64::from(num_bernoulli) * 0.5; // n * p
        let standard_deviation: f64 = (f64::from(num_bernoulli) * 0.5 * 0.5).sqrt(); //  sqrt(n * (p) * (1-p))
        assert_eq!(NUM_BREAKDOWNS as usize, result_u32.len());
        for sample in &result_u32 {
            assert!(
                f64::from(*sample) > mean - 5.0 * standard_deviation
                    && f64::from(*sample) < mean + 5.0 * standard_deviation
            );
        }
        println!("result as u32 {result_u32:?}");
    }
}
