use futures_util::future::try_join_all;
use rand::Rng;
use raw_ipa::error::Error;
use raw_ipa::ff::Field;
use raw_ipa::ff::Fp32BitPrime;
use raw_ipa::protocol::sort::generate_sort_permutation::generate_sort_permutation;
use raw_ipa::protocol::QueryId;
use raw_ipa::test_fixture::{
    make_contexts, make_world_with_config, validate_and_reconstruct, TestWorldConfig,
};
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    let mut config = TestWorldConfig::default();
    config.gateway_config.send_buffer_config.items_in_batch = 1;
    config.gateway_config.send_buffer_config.batch_count = 1000;
    let world = make_world_with_config(QueryId, config);
    let [ctx0, ctx1, ctx2] = make_contexts::<Fp32BitPrime>(&world);
    let num_bits = 64;
    let mut rng = rand::thread_rng();

    let batchsize = 100;

    let mut match_keys: Vec<u64> = Vec::new();
    for _ in 0..batchsize {
        match_keys.push(rng.gen::<u64>());
    }

    let input_len = match_keys.len();
    let mut shares = [
        Vec::with_capacity(input_len),
        Vec::with_capacity(input_len),
        Vec::with_capacity(input_len),
    ];
    for match_key in match_keys.clone() {
        let share_0 = rng.gen::<u64>();
        let share_1 = rng.gen::<u64>();
        let share_2 = match_key ^ share_0 ^ share_1;

        shares[0].push((share_0, share_1));
        shares[1].push((share_1, share_2));
        shares[2].push((share_2, share_0));
    }

    let start = Instant::now();
    let result = try_join_all(vec![
        generate_sort_permutation(ctx0, &shares[0], num_bits),
        generate_sort_permutation(ctx1, &shares[1], num_bits),
        generate_sort_permutation(ctx2, &shares[2], num_bits),
    ])
    .await?;
    let duration = start.elapsed().as_secs_f32();
    println!("benchmark complete after {duration}s");

    assert_eq!(result[0].len(), input_len);
    assert_eq!(result[1].len(), input_len);
    assert_eq!(result[2].len(), input_len);

    let mut mpc_sorted_list: Vec<u128> = (0..input_len).map(|i| i as u128).collect();
    for (i, match_key) in match_keys.iter().enumerate() {
        let index = validate_and_reconstruct(&result[0][i], &result[1][i], &result[2][i]);
        mpc_sorted_list[index.as_u128() as usize] = u128::from(*match_key);
    }

    let mut sorted_match_keys = match_keys.clone();
    sorted_match_keys.sort_unstable();
    for i in 0..input_len {
        assert_eq!(u128::from(sorted_match_keys[i]), mpc_sorted_list[i]);
    }

    Ok(())
}
