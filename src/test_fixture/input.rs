use super::Reconstruct;
use crate::bits::BitArray;
use crate::ff::Field;
use crate::protocol::input::{GenericReportMCShare, GenericReportShare};
use crate::rand::Rng;
use crate::secret_sharing::replicated::semi_honest::{
    AdditiveShare as Replicated, XorShare as XorReplicated,
};
use crate::secret_sharing::IntoShares;
use rand::distributions::Standard;
use rand::prelude::Distribution;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GenericReportTestInput<F: Field, MK: BitArray, BK: BitArray> {
    pub match_key: Option<MK>,
    pub attribution_constraint_id: Option<F>,
    pub timestamp: Option<F>,
    pub is_trigger_report: Option<F>,
    pub breakdown_key: BK,
    pub trigger_value: F,
    pub helper_bit: Option<F>,
    pub aggregation_bit: Option<F>,
}

impl<F, MK, BK> GenericReportTestInput<F, MK, BK>
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    pub fn random<R: Rng>(
        rng: &mut R,
        max_match_key: u128,
        max_breakdown_key: u128,
        max_trigger_value: u128,
    ) -> GenericReportTestInput<F, MK, BK>
    where
        Standard: Distribution<F> + Distribution<MK> + Distribution<BK>,
    {
        GenericReportTestInput {
            match_key: Some(MK::truncate_from(rng.gen_range(0..max_match_key))),
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: Some(F::from(u128::from(rng.gen::<bool>()))),
            breakdown_key: BK::truncate_from(rng.gen_range(0..max_breakdown_key)),
            trigger_value: F::from(rng.gen_range(0..max_trigger_value)),
            helper_bit: None,
            aggregation_bit: None,
        }
    }
}

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

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>> for [GenericReportMCShare<F>; 3]
where
    F: Field,
    MK: BitArray,
    BK: BitArray,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

fn reconstruct_optional_field<F: Field>(x: [&Option<Replicated<F>>; 3]) -> Option<F> {
    if x[0].is_some() {
        Some(
            [
                x[0].as_ref().unwrap(),
                x[1].as_ref().unwrap(),
                x[2].as_ref().unwrap(),
            ]
            .reconstruct(),
        )
    } else {
        None
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

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>> for [&GenericReportMCShare<F>; 3]
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
        let match_key = if s0.match_key.is_some() {
            Some(reconstruct_mod_converted_bits([
                s0.match_key.as_ref().unwrap(),
                s1.match_key.as_ref().unwrap(),
                s2.match_key.as_ref().unwrap(),
            ]))
        } else {
            None
        };
        let reconstructed_optional_values = [
            [
                &s0.attribution_constraint_id,
                &s1.attribution_constraint_id,
                &s2.attribution_constraint_id,
            ],
            [&s0.timestamp, &s1.timestamp, &s2.timestamp],
            [
                &s0.is_trigger_report,
                &s1.is_trigger_report,
                &s2.is_trigger_report,
            ],
            [&s0.helper_bit, &s1.helper_bit, &s2.helper_bit],
            [
                &s0.aggregation_bit,
                &s1.aggregation_bit,
                &s2.aggregation_bit,
            ],
        ]
        .map(|x| reconstruct_optional_field(x));

        GenericReportTestInput {
            breakdown_key,
            trigger_value,
            match_key,
            attribution_constraint_id: reconstructed_optional_values[0],
            timestamp: reconstructed_optional_values[1],
            is_trigger_report: reconstructed_optional_values[2],
            helper_bit: reconstructed_optional_values[3],
            aggregation_bit: reconstructed_optional_values[4],
        }
    }
}
