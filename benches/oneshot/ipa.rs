use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use raw_ipa::{
    error::Error,
    helpers::GatewayConfig,
    test_fixture::{
        generate_random_user_records_in_reverse_chronological_order, test_ipa,
        update_expected_output_for_user, IpaSecurityModel, TestWorld, TestWorldConfig,
    },
};
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    const MAX_BREAKDOWN_KEY: u32 = 16;
    const MAX_TRIGGER_VALUE: u32 = 5;
    const MAX_QUERY_SIZE: usize = 100000;
    const NUM_USERS: usize = 300000;
    const MAX_RECORDS_PER_USER: usize = 1000;

    let mut config = TestWorldConfig::default();
    config.gateway_config =
        GatewayConfig::symmetric_buffers((NUM_USERS * MAX_RECORDS_PER_USER).clamp(16, 1024));

    let random_seed = thread_rng().gen();
    println!("Using random seed: {random_seed}");
    let mut rng = StdRng::seed_from_u64(random_seed);

    let mut total_count = 0;

    let mut random_user_records = Vec::with_capacity(NUM_USERS);
    while random_user_records.len() < NUM_USERS && total_count < MAX_QUERY_SIZE {
        let mut records_for_user = generate_random_user_records_in_reverse_chronological_order(
            &mut rng,
            MAX_RECORDS_PER_USER,
            MAX_BREAKDOWN_KEY,
            MAX_TRIGGER_VALUE,
        );
        if records_for_user.len() > MAX_QUERY_SIZE - total_count {
            records_for_user.truncate(MAX_QUERY_SIZE - total_count);
        }
        total_count += records_for_user.len();
        random_user_records.push(records_for_user);
    }
    let mut raw_data = random_user_records.concat();
    println!("Running test for {:?} records", raw_data.len());
    let start = Instant::now();

    // Sort the records in chronological order
    // This is part of the IPA spec. Callers should do this before sending a batch of records in for processing.
    raw_data.sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let per_user_cap = 3;
    // for per_user_cap in [1, 3] {
        let mut expected_results = vec![0_u32; MAX_BREAKDOWN_KEY.try_into().unwrap()];

        for records_for_user in &random_user_records {
            update_expected_output_for_user(records_for_user, &mut expected_results, per_user_cap);
        }
        let world = TestWorld::new_with(config.clone());

        test_ipa(
            &world,
            &raw_data,
            &expected_results,
            per_user_cap,
            MAX_BREAKDOWN_KEY,
            IpaSecurityModel::Malicious,
        )
        .await;
    // }
    let duration = start.elapsed().as_secs_f32();
    println!("IPA benchmark complete successfully after {duration}s");
    Ok(())
}
