#![cfg(all(feature = "shuttle", test))]

use crate::bits::BitArray40;
use crate::ff::Fp32BitPrime;
use crate::protocol::ipa::ipa;
use crate::rand::thread_rng;
use crate::test_fixture::{IPAInputTestRow, Reconstruct, Runner, TestWorld};

#[test]
fn semi_honest_ipa() {
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                const BATCHSIZE: usize = 5;
                const PER_USER_CAP: u32 = 10;
                const MAX_BREAKDOWN_KEY: u128 = 8;
                const MAX_TRIGGER_VALUE: u128 = 5;
                let max_match_key: u64 = 3;

                let world = TestWorld::new().await;
                let mut rng = thread_rng();

                let records = (0..BATCHSIZE)
                    .map(|_| {
                        IPAInputTestRow::random(
                            &mut rng,
                            max_match_key,
                            MAX_BREAKDOWN_KEY,
                            MAX_TRIGGER_VALUE,
                        )
                    })
                    .collect::<Vec<_>>();

                let result = world
                    .semi_honest(records, |ctx, input_rows| async move {
                        ipa::<Fp32BitPrime, BitArray40>(
                            ctx,
                            &input_rows,
                            PER_USER_CAP,
                            MAX_BREAKDOWN_KEY,
                        )
                        .await
                        .unwrap()
                    })
                    .await
                    .reconstruct();

                assert_eq!(MAX_BREAKDOWN_KEY, result.len() as u128);
            });
        },
        10,
    );
}
