use clap::Parser;
use rand::Rng;
use raw_ipa::error::Error;
use raw_ipa::ff::Fp32BitPrime;
use raw_ipa::ipa_test_input;
use raw_ipa::protocol::ipa::ipa;
// use raw_ipa::protocol::ipa::{ipa_wip_malicious};

use raw_ipa::protocol::{ipa, BreakdownKey, MatchKey};
use raw_ipa::secret_sharing::SharedValue;
use raw_ipa::test_fixture::input::GenericReportTestInput;
use raw_ipa::test_fixture::{Runner, TestWorld, TestWorldConfig};
use std::num::NonZeroUsize;
use std::time::Instant;

#[derive(Debug, Parser)]
pub struct IpaBenchArgs {
    #[arg(long, help = "bits of match key to use in IPA circuit.")]
    pub match_key_bits: Option<u8>,

    #[arg(short, long, help = "ignored")]
    pub bench: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    const BATCHSIZE: usize = 100;
    const MAX_TRIGGER_VALUE: u128 = 5;
    const PER_USER_CAP: u32 = 3;
    const MAX_BREAKDOWN_KEY: u128 = 4;
    let args = IpaBenchArgs::parse();

    let mut config = TestWorldConfig::default();
    config.gateway_config.send_buffer_config.items_in_batch = NonZeroUsize::new(1).unwrap();
    config.gateway_config.send_buffer_config.batch_count = NonZeroUsize::new(1024).unwrap();
    let world = TestWorld::new_with(config).await;
    let mut rng = rand::thread_rng();

    let max_match_key = u128::try_from(BATCHSIZE / 4).unwrap();
    let match_key_bits = if let Some(bits) = args.match_key_bits {
        bits
    } else {
        u8::try_from(MatchKey::BITS).unwrap()
    };

    assert!(
        u32::from(match_key_bits) <= MatchKey::BITS,
        "Requested to use more bits than available in match keys"
    );

    let mut records = Vec::with_capacity(BATCHSIZE);

    for _ in 0..BATCHSIZE {
        records.push(ipa_test_input!(
            {
                match_key: rng.gen_range(0..max_match_key),
                is_trigger_report: rng.gen::<u32>(),
                breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE),
            };
            (Fp32BitPrime, MatchKey, BreakdownKey)
        ));
    }

    let start = Instant::now();
    let result = world
        .semi_honest(records, |ctx, input_rows| async move {
            let query = ipa::Query::new(&input_rows, PER_USER_CAP, MAX_BREAKDOWN_KEY)
                .with_match_key_bits(match_key_bits);
            // ipa_wip_malicious::<Fp32BitPrime, MatchKey, BreakdownKey>(
            ipa(ctx, query).await.unwrap()
        })
        .await;

    let duration = start.elapsed();
    println!(
        "rows={BATCHSIZE}/match key bits={match_key_bits} benchmark complete after {duration:?}"
    );

    assert_eq!(MAX_BREAKDOWN_KEY, result[0].len().try_into().unwrap());
    Ok(())
}
