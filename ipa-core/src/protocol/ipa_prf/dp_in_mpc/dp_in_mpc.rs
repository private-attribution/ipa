// DP in MPC

use futures_util::stream;
use crate::{error::Error, ff::{Field, boolean_array::BA4}, protocol::{
    context::Context,
    prss::SharedRandomness,
}, protocol, secret_sharing::{
    replicated::semi_honest::AdditiveShare as Replicated, FieldSimd,
    Vectorizable,
}};
use crate::ff::boolean::Boolean;
use crate::ff::boolean_array::BA8;
use crate::protocol::ipa_prf::aggregation::aggregate_values;
use crate::protocol::ipa_prf::boolean_ops::addition_sequential::integer_add;
use crate::protocol::prss::PrssIndex;
use crate::secret_sharing::BitDecomposed;
// use crate::protocol::ipa_prf::Step;
// use crate::secret_sharing::replicated::malicious::AdditiveShare;
// use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
use ipa_macros::Step;
use crate::protocol::RecordId;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare;

#[derive(Step)]
pub(crate) enum Step {
    NoiseGen,
    #[dynamic(32)]
    ApplyNoise(usize),
}

#[cfg(test)]
pub async fn add_dp_noise<C, const B: usize,OV>(
    ctx: C,
    histogram_bin_values: &Vec<_>,
    num_histogram_bins: u32,
    x: _,
) -> Result<BitDecomposed<Replicated<Boolean,B>>, Error>
    where
        C: Context,
{

    /// Step 1:  Generate Bernoulli's with PRSS
    /// sample a stream of `total_bits = num_bernoulli * B` bit from PRSS where B is number of histogram bins
    /// and num_bernoulli is the number of Bernoulli samples to sum to get a sample from a Binomial
    /// distribution with the desired epsilon, delta
    let num_bernoulli: u32 = 1000;
    let total_bits = num_bernoulli * num_histogram_bins;
    let bits =1;
    let all_bernoulli_bits : BitDecomposed<Replicated<Boolean,B>> = ctx.prss().generate_with(RecordId::from(0_u32),bits ); // like Andy's example https://github.com/andyleiserson/ipa/commit/a5093b51b6338b701f9d90274eee81f88bc14b99
    let mut vector_input_to_agg: Vec<_>;
    for i in 0..num_bernoulli {
        let element : Replicated<Boolean,B> = ctx.prss().generate_with(RecordId::from(i),bits );
        vector_input_to_agg.push(element);
    }

    /// Step 2: Convert to input from needed for aggregate_values
    /// may need to transpose to be vectorized by B, the number of histogram bins, which is how
    /// aggregation calls `aggregate_values` and similar to how `feature_label_dot_product` uses
    /// number of features
    aggregation_input = Box::pin(stream::iter(vector_input_to_agg.into_iter()));

    /// Step 3: Call `aggregate_values` to sum up Bernoulli noise.
    let noise_gen_ctx  = ctx.narrow(&Step::NoiseGen); // define a step NoiseGen
    let noise_vector = aggregate_values::<_, B,OV>(noise_gen_ctx, aggregation_input, num_bernoulli).await;


    /// Step 4:  Add DP noise to output values
    let apply_noise_ctx =  ctx.narrow(&Step::ApplyNoise).set_total_records(1);
    let histogram_noised = integer_add(apply_noise_ctx, RecordID::FIRST,noise_vector, histogram_bin_values));

    /// Step 5 Transpose output representation
    /// TODO
    Ok(histogram_noised)
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::protocol::ipa_prf::dp_in_mpc::dp_in_mpc::{add_dp_noise};
    use rand::distributions::{Distribution};
    use crate::{ff::{Field, Fp31, Fp32BitPrime, U128Conversions, boolean_array::BA4}, helpers::TotalRecords, protocol::{
        basics::{SecureMul},
        context::Context,
        RecordId,
    }, protocol, rand::{thread_rng, Rng}, secret_sharing::replicated::semi_honest::AdditiveShare as Replicated, seq_join::SeqJoin, test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld}};
    use async_trait::async_trait;
    use crate::ff::boolean::Boolean;
    use crate::ff::boolean_array::BA8;
    use crate::secret_sharing::replicated::malicious::AdditiveShare;
    use crate::protocol::ipa_prf::boolean_ops::addition_sequential::integer_add;
    use crate::protocol::ipa_prf::dp_in_mpc;
    use crate::secret_sharing::BitDecomposed;


    fn input_row<const B: usize>(bit_width: usize, values: &[u32]) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();

        BitDecomposed::decompose(bit_width, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }

    #[tokio::test]
    pub async fn test_four_breakdowns(){
        let world = TestWorld::default();
        // const OUTPUT_WIDTH : u32 = 16;
        type Output_Value = BA8;
        const NUM_BREAKDOWNS: u32 = 4;
        let input = input_row(8, &[10,8,6,41]);
        let result = world.semi_honest(
            input.into_iter(),
            | ctx , input | async move {
                add_dp_noise(ctx, &input,NUM_BREAKDOWNS,Output_Value).await.unwrap()
            }).await;
    }


}
