use crate::protocol::IpaProtocolStep::ModulusConversion;
use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{context::Context, RecordId},
    secret_sharing::{Replicated, SecretSharing, XorReplicated},
};
use async_trait::async_trait;
use futures::future::try_join_all;
use std::iter::{repeat, zip};

use super::context::SemiHonestContext;
use super::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use super::sort::apply_sort::shuffle::Resharable;
use super::sort::generate_permutation::generate_permutation;
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortToMatchKeys,
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
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortToMatchKeys => "sort_keys",
            Self::ApplySortToSidecarData => "sort_values",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::PerformAttribution => "attribution",
            Self::PerformUserCapping => "user_capping",
        }
    }
}

#[async_trait]
impl<F: Field> Resharable<F> for Vec<Replicated<F>> {
    type Share = Replicated<F>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        // try_join_all(
        //     self.iter().map(|x| {
        //         let c = ctx.narrow("foo");
        //         async move {
        //             c.reshare(x, record_id, to_helper).await
        //         }
        //     })
        // ).await
        let result = Vec::with_capacity(self.len());
        for elem in self {
            let r = ctx.reshare(elem, record_id, to_helper).await?;
            result.push(r);
        }
        Ok(result)
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

    let sorted_match_keys = sort_permutation.apply(ctx.narrow(&Step::ApplySortToMatchKeys), converted_shares).await.unwrap();
    //let sorted_other_inputs = sort_permutation.apply(ctx, shares_of_other_inputs).await.unwrap();

    let futures = zip(repeat(ctx), sorted_match_keys.iter())
        .zip(sorted_match_keys.iter().skip(1))
        .enumerate()
        .map(|(i, ((ctx, mk), next_mk))| {
            let record_id = RecordId::from(i);
            async move { bitwise_equal(ctx, record_id, &mk, next_mk).await }
        });
    let mut is_trigger_bits = try_join_all(futures).await?;
    Ok(is_trigger_bits)
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