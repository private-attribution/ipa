use crate::protocol::IpaProtocolStep::ModulusConversion;
use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{context::Context, RecordId},
    secret_sharing::{Replicated, SecretSharing, XorReplicated},
};
use futures::future::try_join_all;
use std::iter::{repeat, zip};

use super::context::SemiHonestContext;
use super::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use super::sort::generate_permutation::generate_permutation;
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortToSidecarData,
    ComputeHelperBits,
    PerformAttribution,
    PerformUserCapping,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::GenSortPermutationFromMatchKeys => "sort_by_match_key",
            Self::ApplySortToSidecarData => "sort_values",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::PerformAttribution => "attribution",
            Self::PerformUserCapping => "user_capping",
        }
    }
}

/// # Errors
/// Propagates errors from `xor_specialized_1`
pub async fn ipa<F, S>(
    ctx: SemiHonestContext<'_, F>,
    mk_shares: &[XorReplicated],
    num_bits: u32,
    _other_inputs: &[[F; 3]],
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    let local_lists = convert_all_bits_local(ctx.role(), &mk_shares, num_bits);
    let converted_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &local_lists,
    )
    .await
    .unwrap();
    let sort_permutation = generate_permutation(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_shares,
        num_bits,
    )
    .await
    .unwrap();

    let sorted_match_keys = sort_permutation.apply(ctx, converted_shares).await.unwrap();
    //let sorted_other_inputs = sort_permutation.apply(ctx, shares_of_other_inputs).await.unwrap();

    let futures = sorted_match_keys
        .iter()
        .zip(sorted_match_keys.iter.skip(1))
        .enumerate()
        .map(|(i, (mk, next_mk))| {
            let record_id = RecordId::from(i);
            let c = ctx;
            async move { bitwise_equal(c, record_id, mk, next_mk).await }
        });
    let mut is_trigger_bits = Vec::with_capacity(sorted_match_keys.len());
    is_trigger_bits.push(F::ZERO);
    is_trigger_bits.append(try_join_all(futures).await.unwrap());
    is_trigger_bits
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::ipa;
    use crate::ff::{Field, Fp32BitPrime};
    use crate::helpers::{Direction, Role};
    use crate::protocol::boolean::bitwise_equal::bitwise_equal;
    use crate::protocol::context::Context;
    use crate::protocol::malicious::MaliciousValidator;
    use crate::rand::thread_rng;
    use crate::secret_sharing::Replicated;
    use crate::{
        error::Error,
        ff::Fp31,
        protocol::{
            modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple},
            QueryId, RecordId,
        },
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };
    use proptest::prelude::Rng;

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;

        let world = TestWorld::new(QueryId);
        let mut rng = thread_rng();

        //   match key, is_trigger, breakdown_key, trigger_value
        let records = [
            [123456789_u32, 0, 1, 0],
            [123456789_u32, 0, 2, 0],
            [683625482_u32, 0, 1, 0],
            [123456789_u32, 1, 0, 5],
            [683625482_u32, 1, 0, 2],
        ];
        let match_keys = records
            .iter()
            .map(|record| MaskedMatchKey::mask(record[0]))
            .collect::<Vec<_>>();

        let mut other_inputs = records
            .iter()
            .map(|record| {
                let c = Fp32BitPrime::from;
                [c(record[1]), c(record[2]), c(record[3])]
            })
            .collect::<Vec<_>>();

        let result = world
            .semi_honest(
                (match_keys, other_inputs),
                |ctx, (mk_shares, shares_of_other_inputs)| async move {
                    ipa(ctx, &mk_shares, 40, &other_inputs).await.unwrap()
                },
            )
            .await;
    }
}
