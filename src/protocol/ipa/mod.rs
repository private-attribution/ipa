use std::iter::{repeat, zip};

use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    protocol::{
        attribution::{
            accumulate_credit::accumulate_credit, aggregate_credit::aggregate_credit,
            credit_capping::credit_capping, AttributionInputRow,
        },
        context::Context,
        sort::{
            apply_sort::apply_sort_permutation,
            generate_permutation::generate_permutation_and_reveal_shuffled,
        },
        RecordId,
    },
    secret_sharing::{Replicated, XorReplicated},
};
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};

use super::{attribution::AggregateCreditOutputRow, context::SemiHonestContext};
use super::{
    modulus_conversion::{convert_all_bits, convert_all_bits_local, transpose},
    sort::apply_sort::shuffle::Resharable,
    Substep,
};
use crate::protocol::boolean::bitwise_equal::bitwise_equal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ModulusConversionForMatchKeys,
    GenSortPermutationFromMatchKeys,
    ApplySortPermutation,
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ModulusConversionForMatchKeys => "mod_conv_match_key",
            Self::GenSortPermutationFromMatchKeys => "gen_sort_permutation_from_match_keys",
            Self::ApplySortPermutation => "apply_sort_permutation",
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
        }
    }
}
pub enum IPAInputRowResharableStep {
    MatchKeyShares,
    TriggerBit,
    BreakdownKey,
    TriggerValue,
}

impl Substep for IPAInputRowResharableStep {}

impl AsRef<str> for IPAInputRowResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::MatchKeyShares => "match_key_shares",
            Self::TriggerBit => "is_trigger_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::TriggerValue => "trigger_value",
        }
    }
}

pub struct IPAInputRow<F: Field> {
    pub mk_shares: XorReplicated,
    pub is_trigger_bit: Replicated<F>,
    pub breakdown_key: Replicated<F>,
    pub trigger_value: Replicated<F>,
}

struct IPAModulusConvertedInputRow<F: Field> {
    mk_shares: Vec<Replicated<F>>,
    is_trigger_bit: Replicated<F>,
    breakdown_key: Replicated<F>,
    trigger_value: Replicated<F>,
}

#[async_trait]
impl<F: Field> Resharable<F> for IPAModulusConvertedInputRow<F>
where
    F: Sized,
{
    type Share = Replicated<F>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_mk_shares = self.mk_shares.reshare(
            ctx.narrow(&IPAInputRowResharableStep::MatchKeyShares),
            record_id,
            to_helper,
        );
        let f_is_trigger_bit = ctx.narrow(&IPAInputRowResharableStep::TriggerBit).reshare(
            &self.is_trigger_bit,
            record_id,
            to_helper,
        );
        let f_breakdown_key = ctx
            .narrow(&IPAInputRowResharableStep::BreakdownKey)
            .reshare(&self.breakdown_key, record_id, to_helper);
        let f_trigger_value = ctx
            .narrow(&IPAInputRowResharableStep::TriggerValue)
            .reshare(&self.trigger_value, record_id, to_helper);

        let (mk_shares, mut outputs) = try_join(
            f_mk_shares,
            try_join_all([f_is_trigger_bit, f_breakdown_key, f_trigger_value]),
        )
        .await?;

        Ok(IPAModulusConvertedInputRow {
            mk_shares,
            is_trigger_bit: outputs.remove(0),
            breakdown_key: outputs.remove(0),
            trigger_value: outputs.remove(0),
        })
    }
}

/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[allow(dead_code)]
pub async fn ipa<F>(
    ctx: SemiHonestContext<'_, F>,
    input_rows: &[IPAInputRow<F>],
    num_bits: u32,
    per_user_credit_cap: u32,
    max_breakdown_key: u128,
) -> Result<Vec<AggregateCreditOutputRow<F>>, Error>
where
    F: Field,
{
    let mk_shares = input_rows.iter().map(|x| x.mk_shares).collect::<Vec<_>>();
    let local_lists = convert_all_bits_local(ctx.role(), &mk_shares, num_bits);
    let converted_shares = convert_all_bits(
        &ctx.narrow(&Step::ModulusConversionForMatchKeys),
        &local_lists,
    )
    .await
    .unwrap();
    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GenSortPermutationFromMatchKeys),
        &converted_shares,
        num_bits,
    )
    .await
    .unwrap();
    let converted_shares = transpose(&converted_shares);

    let combined_match_keys_and_sidecar_data = input_rows
        .iter()
        .zip(converted_shares.into_iter())
        .map(|(input_row, mk_shares)| IPAModulusConvertedInputRow {
            mk_shares,
            is_trigger_bit: input_row.is_trigger_bit.clone(),
            breakdown_key: input_row.breakdown_key.clone(),
            trigger_value: input_row.trigger_value.clone(),
        })
        .collect::<Vec<_>>();

    let sorted_rows = apply_sort_permutation(
        ctx.narrow(&Step::ApplySortPermutation),
        combined_match_keys_and_sidecar_data,
        &sort_permutation,
    )
    .await
    .unwrap();

    let futures = zip(
        repeat(ctx.narrow(&Step::ComputeHelperBits)),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(ctx, record_id, &row.mk_shares, &next_row.mk_shares).await }
    });
    let helper_bits = Some(Replicated::ZERO)
        .into_iter()
        .chain(try_join_all(futures).await?);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| AttributionInputRow {
            is_trigger_bit: row.is_trigger_bit,
            helper_bit: hb,
            breakdown_key: row.breakdown_key,
            credit: row.trigger_value,
        })
        .collect::<Vec<_>>();

    let accumulated_credits =
        accumulate_credit(ctx.narrow(&Step::AccumulateCredit), &attribution_input_rows).await?;

    let user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    aggregate_credit(
        ctx.narrow(&Step::AggregateCredit),
        &user_capped_credits,
        max_breakdown_key,
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
pub mod tests {
    use super::{ipa, IPAInputRow};
    use crate::secret_sharing::IntoShares;
    use crate::{ff::Fp32BitPrime, rand::thread_rng};
    use crate::{
        ff::{Field, Fp31},
        protocol::QueryId,
        secret_sharing::Replicated,
        test_fixture::{MaskedMatchKey, Reconstruct, Runner, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution, Rng};

    #[derive(Debug)]
    pub struct IPAInputTestRow {
        match_key: u64,
        is_trigger_bit: u128,
        breakdown_key: u128,
        trigger_value: u128,
    }

    impl<F> IntoShares<IPAInputRow<F>> for IPAInputTestRow
    where
        F: Field + IntoShares<Replicated<F>>,
        Standard: Distribution<F>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [IPAInputRow<F>; 3] {
            let match_key_shares = MaskedMatchKey::mask(self.match_key).share_with(rng);
            let [itb0, itb1, itb2] = F::from(self.is_trigger_bit).share_with(rng);
            let [bdk0, bdk1, bdk2] = F::from(self.breakdown_key).share_with(rng);
            let [tv0, tv1, tv2] = F::from(self.trigger_value).share_with(rng);
            [
                IPAInputRow {
                    mk_shares: match_key_shares[0],
                    is_trigger_bit: itb0,
                    breakdown_key: bdk0,
                    trigger_value: tv0,
                },
                IPAInputRow {
                    mk_shares: match_key_shares[1],
                    is_trigger_bit: itb1,
                    breakdown_key: bdk1,
                    trigger_value: tv1,
                },
                IPAInputRow {
                    mk_shares: match_key_shares[2],
                    is_trigger_bit: itb2,
                    breakdown_key: bdk2,
                    trigger_value: tv2,
                },
            ]
        }
    }

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const PER_USER_CAP: u32 = 3;
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];

        let world = TestWorld::new(QueryId);

        //   match key, is_trigger, breakdown_key, trigger_value
        let records = [
            IPAInputTestRow {
                match_key: 12345,
                is_trigger_bit: 0,
                breakdown_key: 1,
                trigger_value: 0,
            },
            IPAInputTestRow {
                match_key: 12345,
                is_trigger_bit: 0,
                breakdown_key: 2,
                trigger_value: 0,
            },
            IPAInputTestRow {
                match_key: 68362,
                is_trigger_bit: 0,
                breakdown_key: 1,
                trigger_value: 0,
            },
            IPAInputTestRow {
                match_key: 12345,
                is_trigger_bit: 1,
                breakdown_key: 0,
                trigger_value: 5,
            },
            IPAInputTestRow {
                match_key: 68362,
                is_trigger_bit: 1,
                breakdown_key: 0,
                trigger_value: 2,
            },
        ];

        let result = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp31>(ctx, &input_rows, 20, PER_USER_CAP, 3)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(EXPECTED.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            // Each element in the `result` is a general purpose `[F; 4]`.
            // For this test case, the first two elements are `breakdown_key`
            // and `credit` as defined by the implementation of `Reconstruct`
            // for `[AggregateCreditOutputRow<F>; 3]`.
            let result = result[i].0.map(|x| x.as_u128());
            assert_eq!(*expected, [result[0], result[1]]);
        }
    }

    #[tokio::test]
    #[allow(clippy::missing_panics_doc)]
    pub async fn random_ipa_no_result_check() {
        const BATCHSIZE: u64 = 100;
        const PER_USER_CAP: u32 = 10;
        const MAX_BREAKDOWN_KEY: u128 = 8;
        const MAX_TRIGGER_VALUE: u128 = 5;
        let matchkeys_upto: u64 = BATCHSIZE / 10;

        let world = TestWorld::new(QueryId);
        let mut rng = thread_rng();

        let mut records: Vec<IPAInputTestRow> = Vec::new();

        for _ in 0..BATCHSIZE {
            let is_trigger_bit = u128::from(rng.gen::<bool>());
            let test_row = IPAInputTestRow {
                match_key: rng.gen_range(0..matchkeys_upto),
                is_trigger_bit,
                breakdown_key: match is_trigger_bit {
                    0 => rng.gen_range(0..MAX_BREAKDOWN_KEY), // Breakdown key is only found in source events
                    1_u128..=u128::MAX => 0,
                },
                trigger_value: is_trigger_bit * rng.gen_range(1..MAX_TRIGGER_VALUE), // Trigger value is only found in trigger events
            };
            println!("{:?}", test_row);
            records.push(test_row);
        }
        let result = world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<Fp32BitPrime>(ctx, &input_rows, 20, PER_USER_CAP, MAX_BREAKDOWN_KEY)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        println!("Attribution Result {:?}", result);
        assert_eq!(MAX_BREAKDOWN_KEY, result.len() as u128);
    }
}
