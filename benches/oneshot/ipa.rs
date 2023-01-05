use raw_ipa::error::Error;
use raw_ipa::ff::Fp32BitPrime;
use raw_ipa::protocol::ipa::ipa;
use raw_ipa::test_fixture::{IPAInputTestRow, Runner, TestWorld, TestWorldConfig};
use std::num::NonZeroUsize;
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    const BATCHSIZE: usize = 100;
    const MAX_TRIGGER_VALUE: u128 = 5;
    const PER_USER_CAP: u32 = 3;
    const MAX_BREAKDOWN_KEY: u128 = 4;

    let mut config = TestWorldConfig::default();
    config.gateway_config.send_buffer_config.items_in_batch = NonZeroUsize::new(1).unwrap();
    config.gateway_config.send_buffer_config.batch_count = NonZeroUsize::new(1024).unwrap();
    let world = TestWorld::new_with(config).await;
    let mut rng = rand::thread_rng();

    let max_match_key = u64::try_from(BATCHSIZE / 4).unwrap();

    let mut records: Vec<IPAInputTestRow> = Vec::with_capacity(BATCHSIZE);

    for _ in 0..BATCHSIZE {
        records.push(IPAInputTestRow::random(
            &mut rng,
            max_match_key,
            MAX_BREAKDOWN_KEY,
            MAX_TRIGGER_VALUE,
        ));
    }

    let start = Instant::now();
    let result = world
        .semi_honest(records, |ctx, input_rows| async move {
            ipa::<Fp32BitPrime>(ctx, &input_rows, 20, PER_USER_CAP, MAX_BREAKDOWN_KEY)
                .await
                .unwrap()
        })
        .await;

    let duration = start.elapsed();
    println!("rows {BATCHSIZE} benchmark complete after {duration:?}");

    assert_eq!(MAX_BREAKDOWN_KEY, result[0].len().try_into().unwrap());
    Ok(())
}
