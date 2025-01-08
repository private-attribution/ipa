// DP in MPC
pub mod step;

use std::{convert::Infallible, f64};

use futures_util::{stream, StreamExt};
use rand_core::{CryptoRng, RngCore};

use crate::{
    error::{
        Error::{self, EpsilonOutOfBounds},
        LengthError,
    },
    ff::{boolean::Boolean, boolean_array::BooleanArray, U128Conversions},
    helpers::{query::DpMechanism, Direction, Role, TotalRecords},
    protocol::{
        boolean::step::ThirtyTwoBitStep,
        context::{
            dzkp_validator::DZKPValidator, Context, DZKPUpgraded, MaliciousProtocolSteps,
            UpgradableContext,
        },
        dp::step::{ApplyDpNoise, DPStep},
        ipa_prf::{
            aggregation::{aggregate_values, aggregate_values_proof_chunk},
            boolean_ops::addition_sequential::integer_add,
            oprf_padding::insecure::OPRFPaddingDp,
            step::IpaPrfStep,
        },
        prss::{FromPrss, SharedRandomness},
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed, FieldSimd, TransposeFrom, Vectorizable,
    },
};

/// For documentation on the Binomial DP noise generation in MPC see
/// [draft-case-ppm-binomial-dp-latest](https://private-attribution.github.io/i-d/draft-case-ppm-binomial-dp.html)
///
/// Struct to hold noise parameters, contains internal values not received from the client
///
/// `epsilon` and `delta` are the privacy parameters for approximate DP.  `epsilon` will
/// generally be in the range `[0.01, 10]` and we default to `5.0`. `delta` will generally be
/// in the range `[1e-6, 1e-10]` and we default to `1e-6`
///
pub struct NoiseParams {
    pub epsilon: f64,
    pub delta: f64,
    pub per_user_credit_cap: u32,
    pub success_prob: f64,
    pub dimensions: f64,
    pub quantization_scale: f64,
    pub ell_1_sensitivity: f64,
    pub ell_2_sensitivity: f64,
    pub ell_infty_sensitivity: f64,
}

impl Default for NoiseParams {
    fn default() -> Self {
        Self {
            epsilon: 5.0,
            delta: 1e-6,
            per_user_credit_cap: 1,
            success_prob: 0.5,
            dimensions: 1.0,
            quantization_scale: 1.0,
            ell_1_sensitivity: 1.0,
            ell_2_sensitivity: 1.0,
            ell_infty_sensitivity: 1.0,
        }
    }
}
const MAX_PROBABILITY: f64 = 1.0;
const MAX_EPSILON: f64 = 20.0;

impl NoiseParams {
    /// # Errors
    /// Will return an error if you try to construct a `NoiseParams` struct with
    /// `success_prob` not in the range [0,1]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epsilon: f64,
        delta: f64,
        per_user_credit_cap: u32,
        success_prob: f64,
        dimensions: f64,
        quantization_scale: f64,
        ell_1_sensitivity: f64,
        ell_2_sensitivity: f64,
        ell_infty_sensitivity: f64,
    ) -> Result<NoiseParams, String> {
        if epsilon <= 0.0 {
            return Err("epsilon must be > 0.0".to_string());
        }
        if delta != 0.0 {
            return Err("delta must be > 0.0".to_string());
        }
        if !(0.0..=MAX_PROBABILITY).contains(&success_prob) {
            return Err("success_prob must be between 0 and 1".to_string());
        }
        if dimensions <= 0.0 {
            return Err("dimensions must be > 0.0".to_string());
        }
        if quantization_scale <= 0.0 {
            return Err("quantization_scale must be > 0.0".to_string());
        }
        if ell_1_sensitivity <= 0.0 {
            return Err("ell_1_sensitivity must be > 0.0".to_string());
        }
        if ell_2_sensitivity <= 0.0 {
            return Err("ell_2_sensitivity must be > 0.0".to_string());
        }
        if ell_infty_sensitivity <= 0.0 {
            return Err("ell_infty_sensitivity must be > 0.0".to_string());
        }
        Ok(NoiseParams {
            epsilon,
            delta,
            per_user_credit_cap,
            success_prob,
            dimensions,
            quantization_scale,
            ell_1_sensitivity,
            ell_2_sensitivity,
            ell_infty_sensitivity,
        })
    }
}

/// # Panics
/// Will panic if there are not enough bits in the outputs size for the noise gen sum. We can't have the noise sum saturate
/// as that would be insecure noise.
/// # Errors
/// may have errors generated in `aggregate_values` also some asserts here
pub async fn gen_binomial_noise<C, const B: usize, OV>(
    ctx: C,
    num_bernoulli: usize,
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
    let ov_bits = OV::BITS;
    tracing::info!("In Binomial DP noise, num_bernoulli = {num_bernoulli}");

    assert!(
        num_bernoulli.ilog2() < ov_bits,
        "not enough bits in output size for noise gen sum; num_bernoulli = {num_bernoulli}. OV::BITS = {ov_bits}"
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
    let noise_vector: Result<BitDecomposed<Replicated<Boolean, { B }>>, Error> =
        aggregate_values::<_, OV, B>(ctx, aggregation_input, num_bernoulli, None).await;
    noise_vector
}
/// `apply_dp_noise` takes the noise distribution parameters (`num_bernoulli` and in the future `quantization_scale`)
/// and the vector of values to have noise added to.
/// It calls `gen_binomial_noise` to create the noise in MPC and applies it
/// # Panics
/// asserts in `gen_binomial_noise` may panic
/// # Errors
/// Result error case could come from transpose
#[tracing::instrument(name = "apply_dp_noise", skip_all)]
pub async fn apply_dp_noise<C, const B: usize, OV>(
    ctx: C,
    histogram_bin_values: BitDecomposed<Replicated<Boolean, B>>,
    num_bernoulli: usize,
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
        .narrow(&ApplyDpNoise::ApplyNoise)
        .set_total_records(TotalRecords::ONE);
    let (histogram_noised, _) = integer_add::<_, ThirtyTwoBitStep, B>(
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

// dp_for_aggregation is currently where the DP parameters epsilon, delta
// are introduced and then from those the parameters of the noise distribution to generate are
// calculated for use in aggregating histograms.  The DP parameters query_epsilon and
// per_user_credit_cap come as inputs to the query with per_user_sensitivity_cap = 2^{SS_BITS}
/// # Errors
/// will propogate errors from `apply_dp_noise`
/// Will return an error epsilon is not in the range (0,`MAX_EPSILON`); we allow very large
/// epsilons to make the noise gen circuit small enough for concurency testing to be possible.
/// # Panics
/// may panic from asserts down in  `gen_binomial_noise`
///
#[allow(clippy::too_many_lines)]
pub async fn dp_for_histogram<C, const B: usize, OV, const SS_BITS: usize>(
    ctx: C,
    histogram_bin_values: BitDecomposed<Replicated<Boolean, B>>,
    dp_params: DpMechanism,
) -> Result<Vec<Replicated<OV>>, Error>
where
    C: UpgradableContext,
    Boolean: Vectorizable<B> + FieldSimd<B>,
    BitDecomposed<Replicated<Boolean, B>>: FromPrss<usize>,
    OV: BooleanArray + U128Conversions,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    Vec<Replicated<OV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<OV>; B], Error = Infallible>,
{
    let steps = MaliciousProtocolSteps {
        protocol: &IpaPrfStep::DifferentialPrivacy,
        validate: &IpaPrfStep::DifferentialPrivacyValidate,
    };
    match dp_params {
        DpMechanism::NoDp => Ok(Vec::transposed_from(&histogram_bin_values)?),
        DpMechanism::Binomial { epsilon } => {
            if epsilon <= 0.0 || epsilon > MAX_EPSILON {
                return Err(EpsilonOutOfBounds);
            }

            let per_user_credit_cap = 2_u32.pow(u32::try_from(SS_BITS).unwrap());

            let dimensions = f64::from(u32::try_from(B).unwrap());

            let noise_params = NoiseParams {
                epsilon,
                per_user_credit_cap,
                ell_1_sensitivity: f64::from(per_user_credit_cap),
                ell_2_sensitivity: f64::from(per_user_credit_cap),
                ell_infty_sensitivity: f64::from(per_user_credit_cap),
                dimensions,
                ..Default::default()
            };

            let num_bernoulli =
                usize::try_from(find_smallest_num_bernoulli(&noise_params)).unwrap();
            let epsilon = noise_params.epsilon;
            let delta = noise_params.delta;
            tracing::info!(
                "In dp_for_histogram with Binomial noise: \
                epsilon = {epsilon}, \
                delta = {delta}, \
                num_breakdowns (dimension) = {dimensions}, \
                per_user_credit_cap = {per_user_credit_cap}, \
                num_bernoulli = {num_bernoulli}"
            );

            let agg_proof_chunk = aggregate_values_proof_chunk(B, 1);
            if num_bernoulli > 2 * agg_proof_chunk {
                // Although it may not be true relative to our current value of
                // TARGET_PROOF_SIZE, I suspect that it is reasonable to validate noise
                // generation with a single proof. If so, it will be quite a bit easier to
                // increase the proof limit, than to split noise generation into multiple
                // proofs. This warning is an encouragement to resolve the situation, one
                // way or another.
                tracing::warn!(
                    "num_bernoulli of {num_bernoulli} may result in excessively large DZKP"
                );
            }

            let dp_validator = ctx.dzkp_validator(steps, num_bernoulli);

            let noisy_histogram = apply_dp_noise::<_, B, OV>(
                dp_validator.context(),
                histogram_bin_values,
                num_bernoulli,
            )
            .await
            .unwrap();

            dp_validator.validate().await?;

            Ok(noisy_histogram)
        }
        DpMechanism::DiscreteLaplace { epsilon } => {
            let noise_params = NoiseParams {
                epsilon,
                per_user_credit_cap: 2_u32.pow(u32::try_from(SS_BITS).unwrap()),
                ..Default::default()
            };

            let truncated_discret_laplace = OPRFPaddingDp::new(
                noise_params.epsilon,
                noise_params.delta,
                noise_params.per_user_credit_cap,
            )?;

            assert!((epsilon - noise_params.epsilon).abs() < 0.001);
            let (mean, _) = truncated_discret_laplace.mean_and_std();
            tracing::info!(
                "In dp_for_histogram with Truncated Discrete Laplace noise: \
                epsilon = {epsilon}, \
                delta = {}, \
                per_user_credit_cap = {}, \
                noise mean (including all three pairs of noise) = {}, \
                OV::BITS = {}",
                noise_params.delta,
                noise_params.per_user_credit_cap,
                mean * 3.0,
                OV::BITS,
            );

            let dp_validator = ctx.dzkp_validator(steps, 1);

            let noised_output = apply_laplace_noise_pass::<_, OV, B>(
                &dp_validator.context().narrow(&DPStep::LaplacePass1),
                histogram_bin_values,
                Role::H1,
                &noise_params,
            )
            .await?;

            let noised_output = apply_laplace_noise_pass::<_, OV, B>(
                &dp_validator.context().narrow(&DPStep::LaplacePass2),
                noised_output,
                Role::H2,
                &noise_params,
            )
            .await?;

            let noised_output = apply_laplace_noise_pass::<_, OV, B>(
                &dp_validator.context().narrow(&DPStep::LaplacePass3),
                noised_output,
                Role::H3,
                &noise_params,
            )
            .await?;

            dp_validator.validate().await?;

            Ok(Vec::transposed_from(&noised_output)?)
        }
    }
}

struct ShiftedTruncatedDiscreteLaplace {
    truncated_discrete_laplace: OPRFPaddingDp,
    shift: u32,
    modulus: u32,
}

impl ShiftedTruncatedDiscreteLaplace {
    /// # Panics
    /// if `bit_size > 32`
    pub fn new(noise_params: &NoiseParams, bit_size: u32) -> Result<Self, Error> {
        // A truncated Discrete Laplace distribution is the same as a truncated Double Geometric distribution.
        // OPRFPaddingDP is currently just a poorly named wrapper on a Truncated Double Geometric
        let truncated_discrete_laplace = OPRFPaddingDp::new(
            noise_params.epsilon,
            noise_params.delta,
            noise_params.per_user_credit_cap,
        )?;
        let shift = truncated_discrete_laplace.get_shift();
        assert!(bit_size <= 32);
        let modulus = if bit_size < 32 {
            2_u32.pow(bit_size)
        } else {
            u32::MAX
        };

        Ok(Self {
            truncated_discrete_laplace,
            shift,
            modulus,
        })
    }

    fn sample<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u32 {
        self.truncated_discrete_laplace.sample(rng)
    }

    pub fn sample_shares<R, OV>(
        &self,
        rng: &mut R,
        direction_to_excluded_helper: Direction,
    ) -> Replicated<OV>
    where
        R: RngCore + CryptoRng,
        OV: BooleanArray + U128Conversions,
    {
        let sample = self.sample(rng);
        let symmetric_sample = sample.wrapping_sub(self.shift) % self.modulus;
        match direction_to_excluded_helper {
            Direction::Left => {
                Replicated::new(OV::ZERO, OV::truncate_from(u128::from(symmetric_sample)))
            }
            Direction::Right => {
                Replicated::new(OV::truncate_from(u128::from(symmetric_sample)), OV::ZERO)
            }
        }
    }
}

/// # Errors
/// will propagate errors from constructing a `truncated_discrete_laplace` distribution.
/// # Panics
/// if `OV::BITS > 32`
pub async fn apply_laplace_noise_pass<C, OV, const B: usize>(
    ctx: &C,
    histogram_bin_values: BitDecomposed<Replicated<Boolean, B>>,
    excluded_helper: Role,
    noise_params: &NoiseParams,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    C: Context,
    OV: BooleanArray + U128Conversions,
    Boolean: Vectorizable<B> + FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<OV>; B], Error = Infallible>,
    Replicated<OV>: ReplicatedSecretSharing<OV>,
{
    let noise_values_array: [Replicated<OV>; B] =
        if let Some(direction_to_excluded_helper) = ctx.role().direction_to(excluded_helper) {
            // Step 1: Helpers `h_i` and `h_i_plus_one` will get the same rng from PRSS
            // and use it to sample the same random Laplace noise sample from TruncatedDoubleGeometric.
            let (mut left, mut right) = ctx.prss_rng();
            let rng = match direction_to_excluded_helper {
                Direction::Left => &mut right,
                Direction::Right => &mut left,
            };
            let shifted_truncated_discrete_laplace =
                ShiftedTruncatedDiscreteLaplace::new(noise_params, OV::BITS)?;
            std::array::from_fn(|_i| {
                shifted_truncated_discrete_laplace.sample_shares(rng, direction_to_excluded_helper)
            })
        } else {
            //  before we can do integer_add we need the excluded Helper to set its shares to zero
            // for these noise values.
            std::array::from_fn(|_i| Replicated::new(OV::ZERO, OV::ZERO))
        };

    let noise_shares_vectorized: BitDecomposed<Replicated<Boolean, B>> =
        BitDecomposed::transposed_from(&noise_values_array).unwrap();

    //  Add DP noise to output values
    let apply_noise_ctx = ctx
        .narrow(&ApplyDpNoise::ApplyNoise)
        .set_total_records(TotalRecords::ONE);
    let (histogram_noised, _) = integer_add::<_, ThirtyTwoBitStep, B>(
        apply_noise_ctx,
        RecordId::FIRST,
        &noise_shares_vectorized,
        &histogram_bin_values,
    )
    .await
    .unwrap();
    Ok(histogram_noised)
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
fn b_p(success_prob: f64) -> f64 {
    (2.0 / 3.0) * (success_prob.powi(2) + (1.0 - success_prob).powi(2)) + 1.0 - 2.0 * success_prob
}
/// equation (12)
fn c_p(success_prob: f64) -> f64 {
    2.0_f64.sqrt()
        * (3.0 * success_prob.powi(3)
            + 3.0 * (1.0 - success_prob).powi(3)
            + 2.0 * success_prob.powi(2)
            + 2.0 * (1.0 - success_prob).powi(2))
}
/// equation (16)
fn d_p(success_prob: f64) -> f64 {
    (4.0 / 3.0) * (success_prob.powi(2) + (1.0 - success_prob).powi(2))
}
/// equation (7)
fn epsilon_constraint(num_bernoulli: u32, noise_params: &NoiseParams) -> f64 {
    let num_bernoulli_f64 = f64::from(num_bernoulli);
    let first_term_num =
        noise_params.ell_2_sensitivity * (2.0 * (1.25 / noise_params.delta).ln()).sqrt();
    let first_term_den = noise_params.quantization_scale
        * (num_bernoulli_f64 * noise_params.success_prob * (1.0 - noise_params.success_prob))
            .sqrt();
    let second_term_num = noise_params.ell_2_sensitivity
        * c_p(noise_params.success_prob)
        * ((10.0 / noise_params.delta).ln()).sqrt()
        + noise_params.ell_1_sensitivity * b_p(noise_params.success_prob);
    let second_term_den = noise_params.quantization_scale
        * num_bernoulli_f64
        * noise_params.success_prob
        * (1.0 - noise_params.success_prob)
        * (1.0 - noise_params.delta / 10.0);
    let third_term_num =
        (2.0 / 3.0) * noise_params.ell_infty_sensitivity * (1.25 / noise_params.delta).ln()
            + noise_params.ell_infty_sensitivity
                * d_p(noise_params.success_prob)
                * (20.0 * noise_params.dimensions / noise_params.delta).ln()
                * (10.0 / noise_params.delta).ln();
    let third_term_den = noise_params.quantization_scale
        * num_bernoulli_f64
        * noise_params.success_prob
        * (1.0 - noise_params.success_prob);
    first_term_num / first_term_den
        + second_term_num / second_term_den
        + third_term_num / third_term_den
}
/// constraint from delta in Thm 1
fn delta_constraint(num_bernoulli: u32, noise_params: &NoiseParams) -> bool {
    let lhs =
        f64::from(num_bernoulli) * noise_params.success_prob * (1.0 - noise_params.success_prob);
    let rhs = (23.0 * (10.0 * noise_params.dimensions / noise_params.delta).ln())
        .max(2.0 * noise_params.ell_infty_sensitivity / noise_params.quantization_scale);
    lhs >= rhs
}
/// error of mechanism in Thm 1
#[cfg(all(test, unit_test))]
fn error(num_bernoulli: u32, noise_params: &NoiseParams) -> f64 {
    noise_params.dimensions
        * noise_params.quantization_scale.powi(2)
        * f64::from(num_bernoulli)
        * noise_params.success_prob
        * (1.0 - noise_params.success_prob)
}
/// for fixed p (and other params), find smallest `num_bernoulli` such that `epsilon < desired_epsilon`
/// # Panics
/// will panic if can't find smallest `num_bernoulli` less than 10M.
#[must_use]
pub fn find_smallest_num_bernoulli(noise_params: &NoiseParams) -> u32 {
    let mut index = 0; // candidate to be smallest `num_beroulli`
    let mut lower: u32 = 1;
    let mut higher: u32 = 10_000_000;
    // binary search to find smallest `num_beroulli`. Binary search
    // like the improved version of template #2 found in this article
    // https://medium.com/@berkkantkoc/a-handy-binary-search-template-that-will-save-you-6b36b7b06b8b
    while lower <= higher {
        let mid: u32 = (higher - lower) / 2 + lower;
        if delta_constraint(mid, noise_params)
            && noise_params.epsilon >= epsilon_constraint(mid, noise_params)
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

/// for a `NoiseParams` struct will return the mean and standard deviation
/// of the binomial noise
#[must_use]
pub fn binomial_noise_mean_std(noise_params: &NoiseParams) -> (f64, f64) {
    let num_bernoulli = find_smallest_num_bernoulli(noise_params);
    let mean: f64 = f64::from(num_bernoulli) * 0.5; // n * p
    let standard_deviation: f64 = (f64::from(num_bernoulli) * 0.5 * 0.5).sqrt(); //  sqrt(n * (p) * (1-p))
    (mean, standard_deviation)
}

#[cfg(all(test, unit_test))]
mod test {

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{
                BooleanArray, BA112, BA16, BA20, BA3, BA32, BA4, BA5, BA6, BA64, BA7, BA8,
            },
            U128Conversions,
        },
        helpers::{query::DpMechanism, Direction},
        protocol::{
            dp::{
                apply_dp_noise, delta_constraint, dp_for_histogram, epsilon_constraint, error,
                find_smallest_num_bernoulli, gen_binomial_noise, NoiseParams,
                ShiftedTruncatedDiscreteLaplace,
            },
            ipa_prf::oprf_padding::insecure::OPRFPaddingDp,
        },
        rand::thread_rng,
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
            BitDecomposed, SharedValue, TransposeFrom,
        },
        sharding::NotSharded,
        telemetry::metrics::BYTES_SENT,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig},
    };
    fn vectorize_input<const B: usize>(
        bit_width: usize,
        values: &[u32],
    ) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();
        BitDecomposed::decompose(bit_width, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }

    fn build_shifted_truncated_discrete_laplace_test<OV>()
    where
        OV: BooleanArray + U128Conversions,
    {
        let noise_params = NoiseParams {
            success_prob: 0.5,
            epsilon: 0.01,
            delta: 1e-6,
            dimensions: 1.0,
            quantization_scale: 1.0,
            ell_1_sensitivity: 1.0,
            ell_2_sensitivity: 1.0,
            ell_infty_sensitivity: 1.0,
            ..Default::default()
        };
        let mut rng = thread_rng();
        let shifted_truncated_discrete_laplace =
            ShiftedTruncatedDiscreteLaplace::new(&noise_params, OV::BITS)
                .expect("Fail test on Error");
        // there is some chance we add 0 noise, especially in smaller fields
        // (e.g., in BA3, and multiple of 3 will also be 3 noise)
        // we attempt this multiple times to try and make sure some noise is being added

        let attempts = 10;

        let mut left_noise_shares: Replicated<OV> = Replicated::new(OV::ZERO, OV::ZERO);
        for _i in 1..attempts {
            left_noise_shares =
                shifted_truncated_discrete_laplace.sample_shares(&mut rng, Direction::Left);
            if left_noise_shares.right() != OV::ZERO {
                break;
            }
        }
        assert_eq!(left_noise_shares.left(), OV::ZERO);
        assert_ne!(left_noise_shares.right(), OV::ZERO);

        let mut right_noise_shares: Replicated<OV> = Replicated::new(OV::ZERO, OV::ZERO);
        for _i in 1..attempts {
            right_noise_shares =
                shifted_truncated_discrete_laplace.sample_shares(&mut rng, Direction::Right);
            if right_noise_shares.left() != OV::ZERO {
                break;
            }
        }
        assert_ne!(right_noise_shares.left(), OV::ZERO);
        assert_eq!(right_noise_shares.right(), OV::ZERO);
    }

    #[test]
    fn test_shifted_truncated_discrete_laplace() {
        build_shifted_truncated_discrete_laplace_test::<BA3>();
        build_shifted_truncated_discrete_laplace_test::<BA4>();
        build_shifted_truncated_discrete_laplace_test::<BA5>();
        build_shifted_truncated_discrete_laplace_test::<BA6>();
        build_shifted_truncated_discrete_laplace_test::<BA7>();
        build_shifted_truncated_discrete_laplace_test::<BA8>();
        build_shifted_truncated_discrete_laplace_test::<BA16>();
        build_shifted_truncated_discrete_laplace_test::<BA20>();
        build_shifted_truncated_discrete_laplace_test::<BA32>();
    }

    #[test]
    #[should_panic(expected = "assertion failed: bit_size <= 32")]
    fn test_shifted_truncated_discrete_laplace_ba64() {
        build_shifted_truncated_discrete_laplace_test::<BA64>();
    }

    #[test]
    #[should_panic(expected = "assertion failed: bit_size <= 32")]
    fn test_shifted_truncated_discrete_laplace_ba112() {
        build_shifted_truncated_discrete_laplace_test::<BA112>();
    }

    /// Test for discrete truncated laplace
    // pub async fn dp_for_histogram<C, const B: usize, OV, const SS_BITS: usize>(
    //     ctx: C,
    //     histogram_bin_values: BitDecomposed<Replicated<Boolean, B>>,
    //     dp_params: DpMechanism,
    // ) -> Result<Vec<Replicated<OV>>, Error>
    #[tokio::test]
    pub async fn test_laplace_noise() {
        type OV = BA8;
        const NUM_BREAKDOWNS: u32 = 16;
        const SS_BITS: usize = 3;
        let epsilon = 2.0;
        let dp_params = DpMechanism::DiscreteLaplace { epsilon };
        let world = TestWorld::default();
        let input_values = [0, 0, 0, 0, 1, 1, 1, 1, 100, 100, 100, 100, 10, 20, 30, 40];

        let input: BitDecomposed<[Boolean; NUM_BREAKDOWNS as usize]> =
            vectorize_input(OV::BITS as usize, &input_values); // bit_width passed here needs to match OV::BITS
        let result = world
            .semi_honest(input, |ctx, input| async move {
                dp_for_histogram::<_, { NUM_BREAKDOWNS as usize }, OV, SS_BITS>(
                    ctx, input, dp_params,
                )
                .await
                .unwrap()
            })
            .await;
        let result_reconstructed: Vec<OV> = result.reconstruct();
        let result_u32: Vec<u32> = result_reconstructed
            .iter()
            .map(|&v| u32::try_from(v.as_u128()).unwrap())
            .collect::<Vec<_>>();
        let per_user_credit_cap = 2_u32.pow(u32::try_from(SS_BITS).unwrap());
        let truncated_discrete_laplace = OPRFPaddingDp::new(epsilon, 1e-6, per_user_credit_cap);
        let (_, std) = truncated_discrete_laplace.unwrap().mean_and_std();
        let three_std = 3.0 * std;
        assert_eq!(NUM_BREAKDOWNS as usize, result_u32.len());
        let tolerance_factor = 20.0;
        for i in 0..result_u32.len() {
            let next_result_f64 = f64::from(result_u32[i]);
            let next_result_f64_shifted = if next_result_f64 > 2.0_f64.powf((OV::BITS - 1).into()) {
                next_result_f64 - 2.0_f64.powf(OV::BITS.into())
            } else {
                next_result_f64
            };

            println!(
                "i = {i}, original = {}, result = {}, shifted is = {next_result_f64_shifted}",
                f64::from(input_values[i]),
                result_u32[i],
            );
            assert!(
                (next_result_f64_shifted - f64::from(input_values[i])).abs() <
                    tolerance_factor * three_std
                , "test failed because noised result is more than {tolerance_factor} standard deviations of the noise distribution \
                from the original input values. This will fail with a small chance of failure"
            );
        }
    }

    #[test]
    fn test_epsilon_simple_aggregation_case() {
        let noise_params = NoiseParams {
            delta: 1e-6,
            dimensions: 1.0,
            quantization_scale: 1.0,
            success_prob: 0.5,
            ell_1_sensitivity: 1.0,
            ell_2_sensitivity: 1.0,
            ell_infty_sensitivity: 1.0,
            ..Default::default()
        };
        let num_bernoulli = 2000;
        assert!(delta_constraint(num_bernoulli, &noise_params));
        let eps = epsilon_constraint(num_bernoulli, &noise_params);
        assert!(eps > 0.6375 && eps < 0.6376, "eps = {eps}");
    }
    #[test]
    fn test_num_bernoulli_simple_aggregation_case() {
        // test with success_prob = 1/2
        let mut noise_params = NoiseParams {
            success_prob: 0.5,
            epsilon: 1.0,
            delta: 1e-6,
            dimensions: 1.0,
            quantization_scale: 1.0,
            ell_1_sensitivity: 1.0,
            ell_2_sensitivity: 1.0,
            ell_infty_sensitivity: 1.0,
            ..Default::default()
        };

        let mut smallest_num_bernoulli = find_smallest_num_bernoulli(&noise_params);
        let err = error(smallest_num_bernoulli, &noise_params);
        assert_eq!(smallest_num_bernoulli, 1483_u32);
        assert!(err <= 370.75 && err > 370.7);

        // test with success_prob = 1/4
        noise_params.success_prob = 0.25;
        smallest_num_bernoulli = find_smallest_num_bernoulli(&noise_params);
        assert_eq!(smallest_num_bernoulli, 1978_u32);

        // test with success_prob = 3/4
        noise_params.success_prob = 0.75;
        smallest_num_bernoulli = find_smallest_num_bernoulli(&noise_params);
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
            .dzkp_semi_honest(input, |ctx, input| async move {
                apply_dp_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                    ctx,
                    input,
                    num_bernoulli.try_into().unwrap(),
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

    // Tests for gen_binomial_noise
    #[tokio::test]
    pub async fn gen_binomial_noise_16_breakdowns() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 16;
        let num_bernoulli: u32 = 10000;
        if std::env::var("EXEC_SLOW_TESTS").is_err() {
            return;
        }
        let config = TestWorldConfig::default().with_timeout_secs(60);
        let world = TestWorld::<NotSharded>::with_config(&config);
        let result: [Vec<Replicated<OutputValue>>; 3] = world
            .dzkp_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli.try_into().unwrap(),
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_reconstructed: Vec<OutputValue> = result.reconstruct();
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
    pub async fn gen_binomial_noise_32_breakdowns() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 32;
        let num_bernoulli: u32 = 2000;
        let config = TestWorldConfig::default().with_timeout_secs(60);
        let world = TestWorld::<NotSharded>::with_config(&config);
        let result: [Vec<Replicated<OutputValue>>; 3] = world
            .dzkp_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli.try_into().unwrap(),
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_reconstructed: Vec<OutputValue> = result.reconstruct();
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
    pub async fn gen_binomial_noise_256_breakdowns() {
        type OutputValue = BA16;
        const NUM_BREAKDOWNS: u32 = 256;
        let num_bernoulli: u32 = 1000;
        let config = TestWorldConfig::default().with_timeout_secs(60);
        let world = TestWorld::<NotSharded>::with_config(&config);
        let result: [Vec<Replicated<OutputValue>>; 3] = world
            .dzkp_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli.try_into().unwrap(),
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_reconstructed: Vec<OutputValue> = result.reconstruct();
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
    async fn semi_honest_measure_bandwidth() {
        // uncomment the print statements in this test and
        // run this test in the terminal to print out bandwidth. Formates best in a large terminal
        // cargo test --release  --lib protocol::dp::test::semi_honest_measure_bandwidth -- --nocapture

        type OutputValue = BA32;
        const NUM_BREAKDOWNS: u32 = 32;
        let world = TestWorld::new_with(
            TestWorldConfig::default()
                .with_timeout_secs(30)
                .enable_metrics(),
        );

        let num_bernoulli: u32 = 1_000;
        let result: [Vec<Replicated<OutputValue>>; 3] = world
            .dzkp_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<_, { NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli.try_into().unwrap(),
                    )
                    .await
                    .unwrap(),
                )
            })
            .await
            .map(Result::unwrap);
        let result_reconstructed: Vec<OutputValue> = result.reconstruct();
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

        let snapshot = world.metrics_snapshot();

        let bytes_sent = snapshot.get_counter(BYTES_SENT);

        // snapshot.print(&mut stdout()).unwrap();
        // println!("num_bernoulli {num_bernoulli}");
        println!("bytes_sent {bytes_sent}");
    }
}
