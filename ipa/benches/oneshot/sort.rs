use ipa::{
    error::Error,
    ff::{Field, Fp32BitPrime, GaloisField, Gf40Bit},
    helpers::GatewayConfig,
    protocol::{
        context::{Context, Validator},
        modulus_conversion::{convert_all_bits, convert_all_bits_local},
        sort::generate_permutation_opt::generate_permutation_opt,
        MatchKey,
    },
    secret_sharing::SharedValue,
    test_fixture::{join3, Reconstruct, Runner, TestWorld, TestWorldConfig},
};
use rand::Rng;
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    const BATCHSIZE: usize = 100;
    const NUM_MULTI_BITS: u32 = 3;
    type BenchField = Fp32BitPrime;

    let config = TestWorldConfig {
        gateway_config: GatewayConfig::new(BATCHSIZE.clamp(4, 1024)),
        ..TestWorldConfig::default()
    };
    let world = TestWorld::new_with(config);
    let [ctx0, ctx1, ctx2] = world.contexts();
    let mut rng = rand::thread_rng();

    let mut match_keys: Vec<MatchKey> = Vec::with_capacity(BATCHSIZE);

    for _ in 0..BATCHSIZE {
        match_keys.push(rng.gen::<MatchKey>());
    }

    let converted_shares = world
        .semi_honest(match_keys.clone(), |ctx, match_key| async move {
            convert_all_bits::<BenchField, _, _>(
                &ctx,
                &convert_all_bits_local(ctx.role(), match_key.into_iter()),
                Gf40Bit::BITS,
                NUM_MULTI_BITS,
            )
            .await
            .unwrap()
        })
        .await;

    let start = Instant::now();
    let [(v0, r0), (v1, r1), (v2, r2)] = join3(
        generate_permutation_opt(ctx0, converted_shares[0].iter()),
        generate_permutation_opt(ctx1, converted_shares[1].iter()),
        generate_permutation_opt(ctx2, converted_shares[2].iter()),
    )
    .await;
    let result = join3(v0.validate(r0), v1.validate(r1), v2.validate(r2)).await;

    let duration = start.elapsed().as_secs_f32();
    println!("sort benchmark BATCHSIZE {BATCHSIZE} NUM_MULTI_BITS {NUM_MULTI_BITS} complete after {duration}s");

    assert_eq!(result[0].len(), BATCHSIZE);
    assert_eq!(result[1].len(), BATCHSIZE);
    assert_eq!(result[2].len(), BATCHSIZE);

    let mut mpc_sorted_list: Vec<u128> = (0..BATCHSIZE).map(|i| i as u128).collect();
    for (i, match_key) in match_keys.iter().enumerate() {
        let index = [&result[0][i], &result[1][i], &result[2][i]].reconstruct();
        mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
    }

    let mut sorted_match_keys = match_keys.clone();
    sorted_match_keys.sort_unstable();
    for i in 0..BATCHSIZE {
        assert_eq!(sorted_match_keys[i].as_u128(), mpc_sorted_list[i]);
    }

    Ok(())
}
