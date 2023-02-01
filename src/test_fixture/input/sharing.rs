use super::{GenericReportShare, GenericReportTestInput};
use crate::bits::BitArray;
use crate::ff::Field;
use crate::protocol::attribution::input::{
    AccumulateCreditInputRow, AggregateCreditInputRow, MCAccumulateCreditInputRow,
    MCAggregateCreditOutputRow,
};
use crate::protocol::ipa::IPAInputRow;
use crate::rand::Rng;
use crate::secret_sharing::replicated::semi_honest::{
    AdditiveShare as Replicated, XorShare as XorReplicated,
};
use crate::secret_sharing::IntoShares;
use crate::test_fixture::Reconstruct;
use rand::distributions::Standard;
use rand::prelude::Distribution;

impl<F, MK, BK> IntoShares<GenericReportShare<F, MK, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: BitArray + IntoShares<XorReplicated<MK>>,
    BK: BitArray + IntoShares<XorReplicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [GenericReportShare<F, MK, BK>; 3] {
        let optional_field_values = [
            self.attribution_constraint_id,
            self.timestamp,
            self.is_trigger_report,
            self.helper_bit,
            self.aggregation_bit,
        ];
        let optional_field_shares = optional_field_values.map(|v| match v {
            Some(x) => x.share_with(rng).map(Some),
            None => [None, None, None],
        });

        let [mk0, mk1, mk2] = match self.match_key {
            Some(mk) => MK::truncate_from(mk.as_u128()).share_with(rng).map(Some),
            None => [None, None, None],
        };
        let [bk0, bk1, bk2] = BK::truncate_from(self.breakdown_key.as_u128()).share_with(rng);
        let [tv0, tv1, tv2] = self.trigger_value.share_with(rng);

        [
            GenericReportShare {
                match_key: mk0,
                breakdown_key: bk0,
                trigger_value: tv0,
                attribution_constraint_id: optional_field_shares[0][0].clone(),
                timestamp: optional_field_shares[1][0].clone(),
                is_trigger_report: optional_field_shares[2][0].clone(),
                helper_bit: optional_field_shares[3][0].clone(),
                aggregation_bit: optional_field_shares[4][0].clone(),
            },
            GenericReportShare {
                match_key: mk1,
                breakdown_key: bk1,
                trigger_value: tv1,
                attribution_constraint_id: optional_field_shares[0][1].clone(),
                timestamp: optional_field_shares[1][1].clone(),
                is_trigger_report: optional_field_shares[2][1].clone(),
                helper_bit: optional_field_shares[3][1].clone(),
                aggregation_bit: optional_field_shares[4][1].clone(),
            },
            GenericReportShare {
                match_key: mk2,
                breakdown_key: bk2,
                trigger_value: tv2,
                attribution_constraint_id: optional_field_shares[0][2].clone(),
                timestamp: optional_field_shares[1][2].clone(),
                is_trigger_report: optional_field_shares[2][2].clone(),
                helper_bit: optional_field_shares[3][2].clone(),
                aggregation_bit: optional_field_shares[4][2].clone(),
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<AccumulateCreditInputRow<F, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: BitArray + IntoShares<XorReplicated<MK>>,
    BK: BitArray + IntoShares<XorReplicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AccumulateCreditInputRow<F, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            AccumulateCreditInputRow {
                is_trigger_report: s0.is_trigger_report.unwrap(),
                helper_bit: s0.helper_bit.unwrap(),
                breakdown_key: s0.breakdown_key,
                trigger_value: s0.trigger_value,
            },
            AccumulateCreditInputRow {
                is_trigger_report: s1.is_trigger_report.unwrap(),
                helper_bit: s1.helper_bit.unwrap(),
                breakdown_key: s1.breakdown_key,
                trigger_value: s1.trigger_value,
            },
            AccumulateCreditInputRow {
                is_trigger_report: s2.is_trigger_report.unwrap(),
                helper_bit: s2.helper_bit.unwrap(),
                breakdown_key: s2.breakdown_key,
                trigger_value: s2.trigger_value,
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<AggregateCreditInputRow<F, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: BitArray + IntoShares<XorReplicated<MK>>,
    BK: BitArray + IntoShares<XorReplicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AggregateCreditInputRow<F, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            AggregateCreditInputRow {
                breakdown_key: s0.breakdown_key,
                credit: s0.trigger_value,
            },
            AggregateCreditInputRow {
                breakdown_key: s1.breakdown_key,
                credit: s1.trigger_value,
            },
            AggregateCreditInputRow {
                breakdown_key: s2.breakdown_key,
                credit: s2.trigger_value,
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<IPAInputRow<F, MK, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: BitArray + IntoShares<XorReplicated<MK>>,
    BK: BitArray + IntoShares<XorReplicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [IPAInputRow<F, MK, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            IPAInputRow {
                mk_shares: s0.match_key.unwrap(),
                is_trigger_bit: s0.is_trigger_report.unwrap(),
                breakdown_key: s0.breakdown_key,
                trigger_value: s0.trigger_value,
            },
            IPAInputRow {
                mk_shares: s1.match_key.unwrap(),
                is_trigger_bit: s1.is_trigger_report.unwrap(),
                breakdown_key: s1.breakdown_key,
                trigger_value: s1.trigger_value,
            },
            IPAInputRow {
                mk_shares: s2.match_key.unwrap(),
                is_trigger_bit: s2.is_trigger_report.unwrap(),
                breakdown_key: s2.breakdown_key,
                trigger_value: s2.trigger_value,
            },
        ]
    }
}

fn reconstruct_mod_converted_bits<F: Field, B: BitArray>(input: [&[Replicated<F>]; 3]) -> B {
    debug_assert!(
        B::BITS as usize == input[0].len()
            && input[0].len() == input[1].len()
            && input[1].len() == input[2].len()
    );
    let mut result = 0;
    for i in 0..B::BITS {
        let bit = [
            &input[0][i as usize],
            &input[1][i as usize],
            &input[2][i as usize],
        ]
        .reconstruct();
        result += bit.as_u128() * (1 << i);
    }
    B::truncate_from(result)
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [MCAccumulateCreditInputRow<F>; 3]
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [&MCAccumulateCreditInputRow<F>; 3]
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        let [s0, s1, s2] = self;

        let breakdown_key = reconstruct_mod_converted_bits([
            &s0.breakdown_key,
            &s1.breakdown_key,
            &s2.breakdown_key,
        ]);
        let trigger_value = [&s0.trigger_value, &s1.trigger_value, &s2.trigger_value].reconstruct();
        let is_trigger_report = [
            &s0.is_trigger_report,
            &s1.is_trigger_report,
            &s2.is_trigger_report,
        ]
        .reconstruct();
        let helper_bit = [&s0.helper_bit, &s1.helper_bit, &s2.helper_bit].reconstruct();

        GenericReportTestInput {
            breakdown_key,
            trigger_value,
            is_trigger_report: Some(is_trigger_report),
            helper_bit: Some(helper_bit),
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            aggregation_bit: None,
        }
    }
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [MCAggregateCreditOutputRow<F>; 3]
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [&MCAggregateCreditOutputRow<F>; 3]
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        let [s0, s1, s2] = self;

        let breakdown_key = reconstruct_mod_converted_bits([
            &s0.breakdown_key,
            &s1.breakdown_key,
            &s2.breakdown_key,
        ]);
        let trigger_value = [&s0.credit, &s1.credit, &s2.credit].reconstruct();

        GenericReportTestInput {
            breakdown_key,
            trigger_value,
            is_trigger_report: None,
            helper_bit: None,
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            aggregation_bit: None,
        }
    }
}
