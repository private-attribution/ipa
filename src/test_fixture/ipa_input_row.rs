use rand::{distributions::Standard, prelude::Distribution};

use crate::bits::BitArray;
use crate::secret_sharing::IntoShares;
use crate::{
    ff::Field,
    protocol::ipa::IPAInputRow,
    rand::Rng,
    secret_sharing::replicated::semi_honest::{
        AdditiveShare as Replicated, XorShare as XorReplicated,
    },
};

#[derive(Debug)]
pub struct IPAInputTestRow {
    pub match_key: u64,
    pub is_trigger_bit: u128,
    pub breakdown_key: u128,
    pub trigger_value: u128,
}

impl IPAInputTestRow {
    pub fn random<R: Rng>(
        rng: &mut R,
        max_matchkey: u64,
        max_breakdown_key: u128,
        max_trigger_value: u128,
    ) -> IPAInputTestRow {
        let is_trigger_bit = u128::from(rng.gen::<bool>());
        IPAInputTestRow {
            match_key: rng.gen_range(0..max_matchkey),
            is_trigger_bit,
            breakdown_key: match is_trigger_bit {
                0 => rng.gen_range(0..max_breakdown_key), // Breakdown key is only found in source events
                1_u128..=u128::MAX => 0,
            },
            trigger_value: is_trigger_bit * rng.gen_range(1..max_trigger_value), // Trigger value is only found in trigger events
        }
    }
}

impl<F, B> IntoShares<IPAInputRow<F, B>> for IPAInputTestRow
where
    F: Field + IntoShares<Replicated<F>>,
    B: BitArray + IntoShares<XorReplicated<B>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [IPAInputRow<F, B>; 3] {
        let [mk0, mk1, mk2] = B::truncate_from(self.match_key).share_with(rng);
        let [itb0, itb1, itb2] = F::from(self.is_trigger_bit).share_with(rng);
        let [bdk0, bdk1, bdk2] = F::from(self.breakdown_key).share_with(rng);
        let [tv0, tv1, tv2] = F::from(self.trigger_value).share_with(rng);
        [
            IPAInputRow {
                mk_shares: mk0,
                is_trigger_bit: itb0,
                breakdown_key: bdk0,
                trigger_value: tv0,
            },
            IPAInputRow {
                mk_shares: mk1,
                is_trigger_bit: itb1,
                breakdown_key: bdk1,
                trigger_value: tv1,
            },
            IPAInputRow {
                mk_shares: mk2,
                is_trigger_bit: itb2,
                breakdown_key: bdk2,
                trigger_value: tv2,
            },
        ]
    }
}
