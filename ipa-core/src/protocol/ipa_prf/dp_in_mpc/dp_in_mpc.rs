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
// use crate::protocol::ipa_prf::Step;
// use crate::secret_sharing::replicated::malicious::AdditiveShare;
// use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
use ipa_macros::Step;
use crate::ff::{CustomArray, U128Conversions};
use crate::protocol::{BooleanProtocols, RecordId};
use crate::protocol::context::UpgradedSemiHonestContext;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare;
use crate::sharding::NotSharded;

#[derive(Step)]
pub(crate) enum Step {
    NoiseGen,
    #[dynamic(32)]
    ApplyNoise(usize),
}

#[cfg(test)]
pub async fn gen_binomial_noise<'ctx, const B: usize,OV>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded,Boolean>,
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
    let mut vector_input_to_agg: Vec<_>;
    for i in 0..num_bernoulli {
        let element : BitDecomposed<Replicated<Boolean,B>> = ctx.prss().generate_with(RecordId::from(i),bits);
        vector_input_to_agg.push(element);
    }

    // Step 2: Convert to input from needed for aggregate_values
    // may need to transpose to be vectorized by B, the number of histogram bins, which is how
    // aggregation calls `aggregate_values` and similar to how `feature_label_dot_product` uses
    // number of features

    // Multiple attempts to get an the stream aggregation_input to be of the appropreate type:
    // Attempt 1)
    // let aggregation_input: Pin<Box<Iter<IntoIter<BitDecomposed<AdditiveShare<Boolean, { B }>>>>>> =
    //     Box::pin(stream::iter(vector_input_to_agg.into_iter()));

    // Attempt 2)
    // let aggregation_input: Pin<Box<dyn Stream<Item = Result<BitDecomposed<AdditiveShare<Boolean, B>>, Error>> + Send>> =
    //     Box::pin(stream::unfold(vector_input_to_agg.into_iter(), |mut iter| async move {
    //         let next = iter.next();
    //         match next {
    //             Some(value) => Ok((Ok(value), iter)),
    //             None => Ok((Err(Error::AggregationStream), iter)),
    //         }
    //     }));

    // Attempt 3)
    let aggregation_input: Pin<Box<dyn Stream<Item = Result<BitDecomposed<AdditiveShare<Boolean, B>>, Error>> + Send>> =
        Box::pin(stream::unfold(vector_input_to_agg.into_iter(), |mut iter| {
            async move {
                let next = iter.next();
                match next {
                    Some(value) => Ok((Ok(value), iter)),
                    None => Ok((Err(Error::AggregationStream), iter)),
                }
            }
        })
            .boxed());

    // Step 3: Call `aggregate_values` to sum up Bernoulli noise.

    let noise_vector: Result<BitDecomposed<AdditiveShare<Boolean, { B }>>, Error> = aggregate_values::<OV,B>(
        ctx,
        aggregation_input,
        num_bernoulli as usize).await;
    noise_vector
}


#[cfg(test)]
pub async fn apply_dp_noise<'ctx, const B: usize,OV>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded,Boolean>,
    histogram_bin_values: BitDecomposed<Replicated<Boolean,B>>,
    num_histogram_bins: u32,
    ) -> Result<Vec<Replicated<OV>>, Error>
    where
        Boolean: Vectorizable<B> + FieldSimd<B>,
        BitDecomposed<Replicated<Boolean,B>>: FromPrss<usize>,
        OV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
        Replicated<Boolean, B>: BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded,Boolean>, B>,
{
    assert_eq!(num_histogram_bins, B as u32);
    // in the future there could be some calculation there to go from a passed in
    // epsilon, delta to the num_bernoulli, but for now it is fixed.
    let num_bernoulli: u32 = 1000;
    let noise_gen_ctx = ctx.narrow(&Step::NoiseGen);
    let noise_vector = gen_binomial_noise::<B,OV>(noise_gen_ctx,num_bernoulli,num_histogram_bins);


    // Step 4:  Add DP noise to output values
    let apply_noise_ctx =  ctx.narrow(&Step::ApplyNoise).set_total_records(1);
    let histogram_noised = integer_add::<_,_,B>(
                                                        apply_noise_ctx,
                                                        RecordId::FIRST,
                                                        noise_vector,
                                                        histogram_bin_values);

    // Step 5 Transpose output representation
    Ok(Vec::transposed_from(&histogram_noised)?)

}

#[cfg(all(test, unit_test))]
mod test {
    use crate::protocol::ipa_prf::dp_in_mpc::dp_in_mpc::{apply_dp_noise, gen_binomial_noise};
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

    // #[tokio::test]
    // pub async fn test_apply_dp_noise(){
    //     let world = TestWorld::default();
    //     type Output_Value = BA8;
    //     const NUM_BREAKDOWNS: u32 = 4;
    //     let input = input_row(8, &[10,8,6,41]);
    //     let result = world.semi_honest(
    //         input.into_iter() | ctx,input  | async move {
    //             apply_dp_noise::<_,_,Output_Value>(ctx, &input,NUM_BREAKDOWNS).await.unwrap()
    //         }).await;
    // }

    #[tokio::test]
    pub async fn test_gen_binomial_noise(){
        let world = TestWorld::default();
        // const OUTPUT_WIDTH : u32 = 16;
        type Output_Value = BA8;
        const NUM_BREAKDOWNS: u32 = 4;
        let num_bernoulli : u32 = 1000;
        let input = input_row(8, &[10,8,6,41]); // really no input
        let result = world.upgraded_semi_honest(
            input.into_iter(),
            | ctx , input | async move {
                gen_binomial_noise::<{NUM_BREAKDOWNS as usize},Output_Value>(ctx, num_bernoulli,NUM_BREAKDOWNS).await.unwrap()
            }).await;
    }




}
