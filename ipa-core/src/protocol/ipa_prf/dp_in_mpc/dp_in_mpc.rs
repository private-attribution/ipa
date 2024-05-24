// DP in MPC

use futures_util::{stream, StreamExt};

// use ipa_macros::Step;
use crate::ff::{CustomArray, U128Conversions};
use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        context::{Context, UpgradedSemiHonestContext},
        ipa_prf::aggregation::aggregate_values,
        prss::{FromPrss, SharedRandomness},
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::{AdditiveShare as Replicated, AdditiveShare},
        BitDecomposed, FieldSimd, SharedValue, Vectorizable,
    },
    sharding::NotSharded,
};

#[cfg(test)]
pub async fn gen_binomial_noise<'ctx, const B: usize, OV>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>,
    num_bernoulli: u32,
    num_histogram_bins: u32,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    Boolean: Vectorizable<B> + FieldSimd<B>,
    BitDecomposed<Replicated<Boolean, B>>: FromPrss<usize>,
    OV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Replicated<Boolean, B>:
        BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, B>,
{
    // Step 1:  Generate Bernoulli's with PRSS
    // sample a stream of `total_bits = num_bernoulli * B` bit from PRSS where B is number of histogram bins
    // and num_bernoulli is the number of Bernoulli samples to sum to get a sample from a Binomial
    // distribution with the desired epsilon, delta
    assert_eq!(num_histogram_bins, B as u32);
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
        aggregate_values::<OV, B>(ctx, aggregation_input, num_bernoulli as usize).await;
    noise_vector
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::{
        ff::{boolean::Boolean, boolean_array::BA8},
        protocol::ipa_prf::dp_in_mpc::dp_in_mpc::gen_binomial_noise,
        secret_sharing::BitDecomposed,
        test_fixture::{ReconstructArr, Runner, TestWorld},
    };
    use crate::ff::boolean_array::{BA16, BA32};
    use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
    use crate::secret_sharing::{StdArray, TransposeFrom};
    use crate::test_fixture::Reconstruct;

    fn input_row<const B: usize>(bit_width: usize, values: &[u32]) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();

        BitDecomposed::decompose(bit_width, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }

    #[tokio::test]
    pub async fn test_gen_binomial_noise() {
        let world = TestWorld::default();
        type OutputValue = BA32;
        const NUM_BREAKDOWNS: u32 = 32;
        let num_bernoulli: u32 = 1000;
        let result = world
            .upgraded_semi_honest((), |ctx, ()| async move {
                Vec::transposed_from(
                    &gen_binomial_noise::<{ NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        num_bernoulli,
                        NUM_BREAKDOWNS,
                    )
                    .await
                    .unwrap()
                )
            })
            .await
            .map(Result::unwrap);
        let result_type_confirm : [Vec<OutputValue>; 3] = result;
        let result_reconstructed  = result.reconstruct();
        // let result_reconstructed  = result.reconstruct_arr();
        // let result_nonvectorized = Vec::transposed_from(result_reconstructed);
        // println!("result  {:?}", result_reconstructed);
    }



}
