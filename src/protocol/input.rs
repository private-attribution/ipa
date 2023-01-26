use crate::bits::{BitArray, BitArray40, BitArray8};
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::sort::apply_sort::shuffle::Resharable;
use crate::protocol::Substep;
use crate::protocol::{context::Context, RecordId};
use crate::secret_sharing::replicated::semi_honest::{
    AdditiveShare as Replicated, XorShare as XorReplicated,
};
use async_trait::async_trait;
use futures::future::{try_join4, try_join_all};
use futures::FutureExt;
use std::iter::{repeat, zip};

pub type MatchKey = BitArray40;
pub type BreakdownKey = BitArray8;

// Struct that holds all possible fields of the input to IPA.
#[derive(Debug)]
pub struct GenericReportShare<F: Field, MK: BitArray, BK: BitArray> {
    pub match_key: Option<XorReplicated<MK>>,
    pub attribution_constraint_id: Option<Replicated<F>>,
    pub timestamp: Option<Replicated<F>>,
    pub is_trigger_report: Option<Replicated<F>>,
    pub breakdown_key: XorReplicated<BK>,
    pub trigger_value: Replicated<F>,
    pub helper_bit: Option<Replicated<F>>,
    pub aggregation_bit: Option<Replicated<F>>,
}

#[derive(Debug)]
pub struct GenericReportMCShare<F: Field> {
    pub match_key: Option<Vec<Replicated<F>>>,
    pub attribution_constraint_id: Option<Replicated<F>>,
    pub timestamp: Option<Replicated<F>>,
    pub is_trigger_report: Option<Replicated<F>>,
    pub breakdown_key: Vec<Replicated<F>>,
    pub trigger_value: Replicated<F>,
    pub helper_bit: Option<Replicated<F>>,
    pub aggregation_bit: Option<Replicated<F>>,
}

impl<F: Field, MK: BitArray, BK: BitArray> GenericReportShare<F, MK, BK> {
    pub fn ipa_input(
        match_key: XorReplicated<MK>,
        is_trigger_report: Replicated<F>,
        breakdown_key: XorReplicated<BK>,
        trigger_value: Replicated<F>,
    ) -> GenericReportShare<F, MK, BK> {
        GenericReportShare {
            match_key: Some(match_key),
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: Some(is_trigger_report),
            breakdown_key,
            trigger_value,
            helper_bit: None,
            aggregation_bit: None,
        }
    }
}

impl<F: Field> GenericReportMCShare<F> {
    pub fn ipa_input(
        match_key: Vec<Replicated<F>>,
        is_trigger_report: Replicated<F>,
        breakdown_key: Vec<Replicated<F>>,
        trigger_value: Replicated<F>,
    ) -> GenericReportMCShare<F> {
        GenericReportMCShare {
            match_key: Some(match_key),
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: Some(is_trigger_report),
            breakdown_key,
            trigger_value,
            helper_bit: None,
            aggregation_bit: None,
        }
    }

    pub fn accumulate_protocol_input(
        breakdown_key: Vec<Replicated<F>>,
        trigger_value: Replicated<F>,
        is_trigger_report: Replicated<F>,
        helper_bit: Replicated<F>,
    ) -> GenericReportMCShare<F> {
        GenericReportMCShare {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: Some(is_trigger_report),
            breakdown_key,
            trigger_value,
            helper_bit: Some(helper_bit),
            aggregation_bit: None,
        }
    }

    pub fn aggregate_protocol_input(
        breakdown_key: Vec<Replicated<F>>,
        trigger_value: Replicated<F>,
        helper_bit: Replicated<F>,
        aggregation_bit: Replicated<F>,
    ) -> GenericReportMCShare<F> {
        GenericReportMCShare {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: None,
            breakdown_key,
            trigger_value,
            helper_bit: Some(helper_bit),
            aggregation_bit: Some(aggregation_bit),
        }
    }

    pub fn aggregate_protocol_output(
        breakdown_key: Vec<Replicated<F>>,
        trigger_value: Replicated<F>,
    ) -> GenericReportMCShare<F> {
        GenericReportMCShare {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: None,
            breakdown_key,
            trigger_value,
            helper_bit: None,
            aggregation_bit: None,
        }
    }

    #[must_use]
    pub fn clone_with(&self, trigger_value: Replicated<F>) -> Self {
        GenericReportMCShare {
            match_key: self.match_key.clone(),
            attribution_constraint_id: self.attribution_constraint_id.clone(),
            timestamp: self.timestamp.clone(),
            is_trigger_report: self.is_trigger_report.clone(),
            breakdown_key: self.breakdown_key.clone(),
            trigger_value,
            helper_bit: self.helper_bit.clone(),
            aggregation_bit: self.aggregation_bit.clone(),
        }
    }
}

#[async_trait]
impl<F: Field> Resharable<F> for GenericReportMCShare<F> {
    type Share = Replicated<F>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        // Modulus-converted field wrapped in `Option`
        let c = ctx.clone();
        let f_match_key = match self.match_key.clone() {
            None => async { Ok::<_, Error>(None) }.left_future(),
            Some(v) => async move {
                let a = v
                    .reshare(c.narrow(&ReshareStep::MatchKey), record_id, to_helper)
                    .await
                    .unwrap();
                Ok(Some(a))
            }
            .right_future(),
        };

        // Fields wrapped in `Option`
        let optional_fields = [
            &self.attribution_constraint_id,
            &self.timestamp,
            &self.is_trigger_report,
            &self.helper_bit,
            &self.aggregation_bit,
        ];
        let steps = [
            ReshareStep::AttributionConstraintId,
            ReshareStep::Timestamp,
            ReshareStep::IsTriggerReport,
            ReshareStep::HelperBit,
            ReshareStep::AggregationBit,
        ];
        let f_optional_fields = try_join_all(
            zip(optional_fields, steps)
                .zip(repeat(ctx.clone()))
                .map(|((f, s), c)| match &f {
                    None => async { Ok::<_, Error>(None) }.left_future(),
                    Some(v) => async move {
                        let a = c.narrow(&s).reshare(v, record_id, to_helper).await.unwrap();
                        Ok(Some(a))
                    }
                    .right_future(),
                }),
        );

        // Modulus-converted field
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&ReshareStep::BreakdownKey),
            record_id,
            to_helper,
        );

        // Plain field
        let f_trigger_value = ctx.narrow(&ReshareStep::TriggerValue).reshare(
            &self.trigger_value,
            record_id,
            to_helper,
        );

        let (match_key, mut optional_fields, breakdown_key, trigger_value) = try_join4(
            f_match_key,
            f_optional_fields,
            f_breakdown_key,
            f_trigger_value,
        )
        .await
        .unwrap();

        Ok(GenericReportMCShare {
            match_key,
            attribution_constraint_id: optional_fields.remove(0),
            timestamp: optional_fields.remove(0),
            is_trigger_report: optional_fields.remove(0),
            helper_bit: optional_fields.remove(0),
            aggregation_bit: optional_fields.remove(0),
            breakdown_key,
            trigger_value,
        })
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::{BreakdownKey, MatchKey};
    use crate::ff::Fp31;
    use crate::helpers::Role;
    use crate::protocol::context::Context;
    use crate::protocol::input::GenericReportMCShare;
    use crate::protocol::modulus_conversion::{
        convert_all_bits, convert_all_bits_local, transpose,
    };
    use crate::protocol::sort::apply_sort::Resharable;
    use crate::protocol::RecordId;
    use crate::test_fixture::{GenericReportTestInput, Reconstruct, Runner, TestWorld};
    use futures::future::try_join;
    use rand::{thread_rng, Rng};

    #[tokio::test]
    pub async fn reshare() {
        let mut rng = thread_rng();
        let secret: GenericReportTestInput<Fp31, MatchKey, BreakdownKey> = GenericReportTestInput {
            match_key: Some(rng.gen::<MatchKey>()),
            attribution_constraint_id: Some(rng.gen::<Fp31>()),
            timestamp: Some(rng.gen::<Fp31>()),
            is_trigger_report: Some(rng.gen::<Fp31>()),
            breakdown_key: rng.gen::<BreakdownKey>(),
            trigger_value: rng.gen::<Fp31>(),
            helper_bit: Some(rng.gen::<Fp31>()),
            aggregation_bit: Some(rng.gen::<Fp31>()),
        };

        let world = TestWorld::new().await;

        for &role in Role::all() {
            let new_shares = world
                .semi_honest(secret, |ctx, share| async move {
                    let mk_ctx = ctx.narrow("modulus_conversion_for_mk");
                    let locally_converted_mk_shares =
                        convert_all_bits_local(ctx.role(), &[share.match_key.unwrap()]);
                    let f_converted_mk_shares =
                        convert_all_bits(&mk_ctx, &locally_converted_mk_shares);

                    let bk_ctx = ctx.narrow("modulus_conversion_for_bk");
                    let locally_converted_bk_shares =
                        convert_all_bits_local(ctx.role(), &[share.breakdown_key]);
                    let f_converted_bk_shares =
                        convert_all_bits(&bk_ctx, &locally_converted_bk_shares);

                    let (mut converted_mk_shares, mut converted_bk_shares) =
                        try_join(f_converted_mk_shares, f_converted_bk_shares)
                            .await
                            .unwrap();

                    converted_mk_shares = transpose(&converted_mk_shares);
                    converted_bk_shares = transpose(&converted_bk_shares);

                    let modulus_converted_share = GenericReportMCShare {
                        match_key: Some(converted_mk_shares.remove(0)),
                        attribution_constraint_id: share.attribution_constraint_id.clone(),
                        timestamp: share.timestamp.clone(),
                        is_trigger_report: share.is_trigger_report.clone(),
                        breakdown_key: converted_bk_shares.remove(0),
                        trigger_value: share.trigger_value.clone(),
                        helper_bit: share.helper_bit.clone(),
                        aggregation_bit: share.aggregation_bit.clone(),
                    };

                    modulus_converted_share
                        .reshare(ctx.set_total_records(1), RecordId::from(0), role)
                        .await
                        .unwrap()
                })
                .await;
            assert_eq!(secret, new_shares.reconstruct());
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum ReshareStep {
    MatchKey,
    AttributionConstraintId,
    Timestamp,
    IsTriggerReport,
    BreakdownKey,
    TriggerValue,
    HelperBit,
    AggregationBit,
}

impl Substep for ReshareStep {}

impl AsRef<str> for ReshareStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::MatchKey => "reshare_for_match_key",
            Self::AttributionConstraintId => "reshare_for_attribution_constraint_id",
            Self::Timestamp => "reshare_for_timestamp",
            Self::IsTriggerReport => "reshare_for_is_trigger_bit",
            Self::BreakdownKey => "reshare_for_breakdown_key",
            Self::TriggerValue => "reshare_for_trigger_value",
            Self::HelperBit => "reshare_for_helper_bit",
            Self::AggregationBit => "reshare_for_aggregation_bit",
        }
    }
}
