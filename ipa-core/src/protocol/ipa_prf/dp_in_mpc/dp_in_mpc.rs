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
    _never_used_input: BitDecomposed<Replicated<Boolean, B>>,
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
    use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
    use crate::secret_sharing::{StdArray, TransposeFrom};

    fn input_row<const B: usize>(bit_width: usize, values: &[u32]) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();

        BitDecomposed::decompose(bit_width, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }

    #[tokio::test]
    pub async fn test_gen_binomial_noise() {
        let world = TestWorld::default();
        type OutputValue = BA8;
        const NUM_BREAKDOWNS: u32 = 8;
        let num_bernoulli: u32 = 1000;
        // There is no input to the noise gen circuit; but we have to pass in something
        let never_used_input: BitDecomposed<[Boolean; 8]> = input_row(8, &[0,0,0,0,0,0,0,0]);
        let result :[BitDecomposed<Replicated<Boolean,8>>;3]= world
            .upgraded_semi_honest(never_used_input, |ctx, never_used_input| async move {
                // Vec::transposed_from(
                    gen_binomial_noise::<{ NUM_BREAKDOWNS as usize }, OutputValue>(
                        ctx,
                        never_used_input,
                        num_bernoulli,
                        NUM_BREAKDOWNS,
                    )
                    .await
                    .unwrap()
                // )
            })
            .await;
            // .unwrap()
            // .reconstruct_arr();
        let result_reconstructed : BitDecomposed<BA8> = result.reconstruct_arr();
        // let result_transposed = Vec::transposed_from(result); //not working to transpose
        println!("result  {:?}", result_reconstructed);
        println!("************************************** PRINTING IN TEST ***********************************88")
    }

    #[test]
    pub fn test_for_printing(){
        println!(" TEST PRINTING IN TESTS")
    }

    //closure
    //  |, | {  }


}
