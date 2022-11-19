use crate::error::BoxError;
use crate::ff::Field;
use crate::ff::Fp32BitPrime;
use crate::protocol::sort::generate_sort_permutation::generate_sort_permutation;
use crate::protocol::QueryId;
use crate::test_fixture::{make_contexts, make_world, validate_and_reconstruct};
use futures_util::future::try_join_all;
use rand::Rng;
use std::iter::zip;

/// Executes the sort circuit.
/// todo: make rounds, bits arguments to this function
///
/// ## Panics
/// When sort panicked
/// ## Errors
/// When sort returned an error
pub async fn execute_sort() -> Result<(), BoxError> {
    const ROUNDS: usize = 50;
    const NUM_BITS: u8 = 24;
    const MASK: u64 = u64::MAX >> (64 - NUM_BITS);

    let world = make_world(QueryId);
    let [ctx0, ctx1, ctx2] = make_contexts::<Fp32BitPrime>(&world);
    let mut rng = rand::thread_rng();

    let mut match_keys: Vec<u64> = Vec::new();
    for _ in 0..ROUNDS {
        match_keys.push(rng.gen::<u64>() & MASK);
    }

    let mut shares = [
        Vec::with_capacity(ROUNDS),
        Vec::with_capacity(ROUNDS),
        Vec::with_capacity(ROUNDS),
    ];
    for match_key in match_keys.clone() {
        let share_0 = rng.gen::<u64>() & MASK;
        let share_1 = rng.gen::<u64>() & MASK;
        let share_2 = match_key ^ share_0 ^ share_1;

        shares[0].push((share_0, share_1));
        shares[1].push((share_1, share_2));
        shares[2].push((share_2, share_0));
    }

    let [result0, result1, result2] = <[_; 3]>::try_from(
        try_join_all([
            generate_sort_permutation(ctx0, &shares[0], NUM_BITS),
            generate_sort_permutation(ctx1, &shares[1], NUM_BITS),
            generate_sort_permutation(ctx2, &shares[2], NUM_BITS),
        ])
        .await?,
    )
    .unwrap();

    assert_eq!(result0.len(), ROUNDS);
    assert_eq!(result1.len(), ROUNDS);
    assert_eq!(result2.len(), ROUNDS);

    let mut mpc_sorted_list: Vec<u128> = (0..ROUNDS).map(|i| i as u128).collect();
    for (match_key, (r0, (r1, r2))) in zip(match_keys.iter(), zip(result0, zip(result1, result2))) {
        let index = validate_and_reconstruct(&r0, &r1, &r2);
        mpc_sorted_list[index.as_u128() as usize] = u128::from(*match_key);
    }

    let mut sorted_match_keys = match_keys.clone();
    sorted_match_keys.sort_unstable();
    for i in 0..ROUNDS {
        assert_eq!(u128::from(sorted_match_keys[i]), mpc_sorted_list[i]);
    }

    Ok(())
}
