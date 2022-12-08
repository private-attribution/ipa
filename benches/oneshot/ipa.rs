use rand::thread_rng;
use raw_ipa::error::Error;
use raw_ipa::ff::{Field, Fp32BitPrime};
use raw_ipa::protocol::ipa::ipa;
use raw_ipa::protocol::ipa::IPAInputRow;
use raw_ipa::protocol::QueryId;
use raw_ipa::secret_sharing::Replicated;
use raw_ipa::test_fixture::{IntoShares, MaskedMatchKey, Runner, TestWorld, TestWorldConfig};
use std::time::Instant;

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

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    let mut config = TestWorldConfig::default();
    config.gateway_config.send_buffer_config.items_in_batch = 1;
    config.gateway_config.send_buffer_config.batch_count = 1000;
    let world = TestWorld::new_with(QueryId, config);
    let mut rng = thread_rng();

    const BATCHSIZE: u64 = 100;
    let matchkeys_upto: u64 = BATCHSIZE / 4;
    const MAX_TRIGGER_VALUE: u128 = 5;
    const PER_USER_CAP: u32 = 3;
    const MAX_BREAKDOWN_KEY: u128 = 4;

    let mut records: Vec<IPAInputTestRow> = Vec::new();

    for _ in 0..BATCHSIZE {
        let is_trigger_bit = u128::from(rng.gen::<bool>());
        let test_row = IPAInputTestRow {
            match_key: rng.gen_range(0..matchkeys_upto),
            is_trigger_bit,
            breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
            trigger_value: is_trigger_bit * rng.gen_range(1..MAX_TRIGGER_VALUE),
        };
        println!("{:?}", test_row);
        records.push(test_row);
    }

    let start = Instant::now();
    let result = world
        .semi_honest(records, |ctx, input_rows| async move {
            ipa::<Fp32BitPrime>(ctx, &input_rows, 20, PER_USER_CAP)
                .await
                .unwrap()
        })
        .await;

    let duration = start.elapsed().as_secs_f32();
    println!("rows {BATCHSIZE} benchmark complete after {duration}s");

    println!("Result:");
    println!("{:?}", result);
    assert_ne!(result.len(), 0);
    Ok(())
}
