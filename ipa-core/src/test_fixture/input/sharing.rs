use std::iter::{zip};

use crate::{
    ff::{
        boolean_array::{BooleanArray, BA64},
        U128Conversions,
    },
    rand::Rng,
    report::{EventType, OprfReport},
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated},
        IntoShares,
    },
    test_fixture::{ipa::TestRawDataRecord},
};

const DOMAINS: &[&str] = &[
    "mozilla.com",
    "facebook.com",
    "example.com",
    "subdomain.long-domain.example.com",
];

// TODO: this mostly duplicates the impl for GenericReportTestInput, can we avoid that?
impl<BK, TV, TS> IntoShares<OprfReport<BK, TV, TS>> for TestRawDataRecord
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    TV: BooleanArray + U128Conversions + IntoShares<Replicated<TV>>,
    TS: BooleanArray + U128Conversions + IntoShares<Replicated<TS>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [OprfReport<BK, TV, TS>; 3] {
        let match_key = BA64::try_from(u128::from(self.user_id))
            .unwrap()
            .share_with(rng);
        let timestamp: [Replicated<TS>; 3] = TS::try_from(u128::from(self.timestamp))
            .unwrap()
            .share_with(rng);
        let breakdown_key = BK::try_from(u128::from(self.breakdown_key))
            .unwrap()
            .share_with(rng);
        let trigger_value = TV::try_from(u128::from(self.trigger_value))
            .unwrap()
            .share_with(rng);
        let event_type = if self.is_trigger_report {
            EventType::Trigger
        } else {
            EventType::Source
        };
        let epoch = 1;
        let site_domain = DOMAINS[rng.gen_range(0..DOMAINS.len())].to_owned();

        zip(zip(match_key, zip(timestamp, breakdown_key)), trigger_value)
            .map(
                |((match_key_share, (ts_share, bk_share)), tv_share)| OprfReport {
                    timestamp: ts_share,
                    match_key: match_key_share,
                    event_type,
                    breakdown_key: bk_share,
                    trigger_value: tv_share,
                    epoch,
                    site_domain: site_domain.clone(),
                },
            )
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
