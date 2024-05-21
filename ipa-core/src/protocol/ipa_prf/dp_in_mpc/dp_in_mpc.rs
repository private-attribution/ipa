// DP in MPC

use std::pin::Pin;
use std::vec::IntoIter;
use futures_util::{stream, StreamExt};
use futures_util::stream::Iter;
use tokio_stream::Stream;
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
use crate::protocol::prss::{FromPrss, PrssIndex};
use crate::secret_sharing::{BitDecomposed, SharedValue, TransposeFrom};
use ipa_macros::Step;
use crate::ff::{CustomArray, U128Conversions};
use crate::protocol::{BooleanProtocols, RecordId};
use crate::protocol::context::UpgradedSemiHonestContext;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare;
use crate::sharding::NotSharded;



#[cfg(test)]
pub async fn gen_binomial_noise<'ctx, const B: usize,OV>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded,Boolean>,
    never_used_input: BitDecomposed<Replicated<Boolean,B>>,
    num_bernoulli: u32,
    num_histogram_bins: u32,
) -> Result<BitDecomposed<Replicated<Boolean,B>>, Error>
    where
        Boolean: Vectorizable<B> + FieldSimd<B>,
        BitDecomposed<Replicated<Boolean,B>>: FromPrss<usize>,
        OV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
        Replicated<Boolean, B>: BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, B>,
{
    // Step 1:  Generate Bernoulli's with PRSS
    // sample a stream of `total_bits = num_bernoulli * B` bit from PRSS where B is number of histogram bins
    // and num_bernoulli is the number of Bernoulli samples to sum to get a sample from a Binomial
    // distribution with the desired epsilon, delta
    assert_eq!(num_histogram_bins, B as u32);
    let bits = 1;
    let mut vector_input_to_agg: Vec<_> = vec![];
    for i in 0..num_bernoulli {
        let element : BitDecomposed<Replicated<Boolean,B>> = ctx.prss().generate_with(RecordId::from(i),bits);
        vector_input_to_agg.push(element);
    }

    // Step 2: Convert to input from needed for aggregate_values
    let aggregation_input =
        Box::pin(stream::iter(vector_input_to_agg.into_iter()).map(Ok));


    // Step 3: Call `aggregate_values` to sum up Bernoulli noise.
    let noise_vector: Result<BitDecomposed<AdditiveShare<Boolean, { B }>>, Error> = aggregate_values::<OV,B>(
        ctx,
        aggregation_input,
        num_bernoulli as usize).await;
    noise_vector
}


#[cfg(all(test, unit_test))]
mod test {
    use crate::protocol::ipa_prf::dp_in_mpc::dp_in_mpc::{gen_binomial_noise};
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
    use crate::secret_sharing::{BitDecomposed, TransposeFrom};

    fn input_row<const B: usize>(bit_width: usize, values: &[u32]) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();

        BitDecomposed::decompose(bit_width, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }

    #[tokio::test]
    pub async fn test_gen_binomial_noise(){
        let world = TestWorld::default();
        // const OUTPUT_WIDTH : u32 = 16;
        type OutputValue = BA8;
        const NUM_BREAKDOWNS: u32 = 8;
        let num_bernoulli : u32 = 1000;
        let input : BitDecomposed<[Boolean;8]> = input_row(8, &[0,0,0,0,0,0,0,0]); // really no input
        let result = world.upgraded_semi_honest(
            input,
            | ctx , input | async move {
                gen_binomial_noise::<{NUM_BREAKDOWNS as usize},OutputValue>(ctx, input, num_bernoulli,NUM_BREAKDOWNS).await.unwrap()
            }).await;
        let result_reconstructed = result.reconstruct_arr();
        // let result_transposed = Vec::transposed_from(result_reconstructed); //not working to transpose
        // println!("result vectorized: {:?}", result_reconstructed);
    }




}
