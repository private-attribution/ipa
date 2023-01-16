use rand::Rng;
use raw_ipa::error::Error;
use raw_ipa::ff::{Field, Fp32BitPrime};
use raw_ipa::protocol::context::Context;
use raw_ipa::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use raw_ipa::protocol::sort::generate_permutation_opt::generate_permutation_opt;
use raw_ipa::secret_sharing::XorReplicated;
use raw_ipa::test_fixture::{join3, Reconstruct, TestWorld, TestWorldConfig};
use std::num::NonZeroUsize;
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    const BATCHSIZE: usize = 10000;
    const NUM_MULTI_BITS: u32 = 3;

    let mut config = TestWorldConfig::default();
    config.gateway_config.send_buffer_config.items_in_batch = NonZeroUsize::new(1).unwrap();
    config.gateway_config.send_buffer_config.batch_count = NonZeroUsize::new(1024).unwrap();
    let world = TestWorld::new_with(config).await;
    let [ctx0, ctx1, ctx2] = world.contexts::<Fp32BitPrime>();
    let num_bits = 64;
    let mut rng = rand::thread_rng();

    let mut match_keys: Vec<u64> = Vec::new();
    for _ in 0..BATCHSIZE {
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

        shares[0].push(XorReplicated::new(share_0, share_1));
        shares[1].push(XorReplicated::new(share_1, share_2));
        shares[2].push(XorReplicated::new(share_2, share_0));
    }

    let converted_shares = join3(
        convert_all_bits(
            &ctx0,
            &convert_all_bits_local(ctx0.role(), &shares[0], num_bits),
        ),
        convert_all_bits(
            &ctx1,
            &convert_all_bits_local(ctx1.role(), &shares[1], num_bits),
        ),
        convert_all_bits(
            &ctx2,
            &convert_all_bits_local(ctx2.role(), &shares[2], num_bits),
        ),
    )
    .await;

    let start = Instant::now();
    let result = join3(
        generate_permutation_opt(ctx0, &converted_shares[0], num_bits, NUM_MULTI_BITS),
        generate_permutation_opt(ctx1, &converted_shares[1], num_bits, NUM_MULTI_BITS),
        generate_permutation_opt(ctx2, &converted_shares[2], num_bits, NUM_MULTI_BITS),
    )
    .await;
    let duration = start.elapsed().as_secs_f32();
    println!("sort benchmark BATCHSIZE {BATCHSIZE} NUM_MULTI_BITS {NUM_MULTI_BITS} complete after {duration}s");

    assert_eq!(result[0].len(), input_len);
    assert_eq!(result[1].len(), input_len);
    assert_eq!(result[2].len(), input_len);

    let mut mpc_sorted_list: Vec<u128> = (0..input_len).map(|i| i as u128).collect();
    for (i, match_key) in match_keys.iter().enumerate() {
        let index = (&result[0][i], &result[1][i], &result[2][i]).reconstruct();
        mpc_sorted_list[index.as_u128() as usize] = u128::from(*match_key);
    }

    let mut sorted_match_keys = match_keys.clone();
    sorted_match_keys.sort_unstable();
    for i in 0..input_len {
        assert_eq!(u128::from(sorted_match_keys[i]), mpc_sorted_list[i]);
    }

    Ok(())
}
