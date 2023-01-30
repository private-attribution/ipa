use rand::Rng;
use raw_ipa::bits::{BitArray, BitArray40};
use raw_ipa::error::Error;
use raw_ipa::ff::{Field, Fp32BitPrime};
use raw_ipa::protocol::context::Context;
use raw_ipa::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use raw_ipa::protocol::sort::generate_permutation_opt::generate_permutation_opt;
use raw_ipa::secret_sharing::SharedValue;
use raw_ipa::test_fixture::{join3, Reconstruct, Runner, TestWorld, TestWorldConfig};
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
    let mut rng = rand::thread_rng();

    let mut match_keys: Vec<BitArray40> = Vec::with_capacity(BATCHSIZE);

    for _ in 0..BATCHSIZE {
        match_keys.push(rng.gen::<BitArray40>());
    }

    let converted_shares = world
        .semi_honest(match_keys.clone(), |ctx, match_key| async move {
            convert_all_bits(
                &ctx,
                convert_all_bits_local(ctx.role(), &match_key, BitArray40::BITS),
                BitArray40::BITS,
                NUM_MULTI_BITS,
            )
            .await
            .unwrap()
            .collect::<Vec<_>>()
        })
        .await;

    let start = Instant::now();
    let result = join3(
        generate_permutation_opt(ctx0, &converted_shares[0]),
        generate_permutation_opt(ctx1, &converted_shares[1]),
        generate_permutation_opt(ctx2, &converted_shares[2]),
    )
    .await;

    let duration = start.elapsed().as_secs_f32();
    println!("sort benchmark BATCHSIZE {BATCHSIZE} NUM_MULTI_BITS {NUM_MULTI_BITS} complete after {duration}s");

    assert_eq!(result[0].len(), BATCHSIZE);
    assert_eq!(result[1].len(), BATCHSIZE);
    assert_eq!(result[2].len(), BATCHSIZE);

    let mut mpc_sorted_list: Vec<u128> = (0..BATCHSIZE).map(|i| i as u128).collect();
    for (i, match_key) in match_keys.iter().enumerate() {
        let index = (&result[0][i], &result[1][i], &result[2][i]).reconstruct();
        mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
    }

    let mut sorted_match_keys = match_keys.clone();
    sorted_match_keys.sort_unstable();
    for i in 0..BATCHSIZE {
        assert_eq!(sorted_match_keys[i].as_u128(), mpc_sorted_list[i]);
    }

    Ok(())
}
