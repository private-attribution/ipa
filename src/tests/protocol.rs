#![cfg(all(feature = "shuttle", test))]

use crate::ff::Fp32BitPrime;
use crate::ipa_test_input;
use crate::protocol::ipa::ipa;
use crate::protocol::{BreakdownKey, MatchKey};
use crate::rand::{thread_rng, Rng};
use crate::test_fixture::input::GenericReportTestInput;
use crate::test_fixture::{Reconstruct, Runner, TestWorld};

#[test]
fn semi_honest_ipa() {
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                const BATCHSIZE: usize = 5;
                const PER_USER_CAP: u32 = 10;
                const MAX_BREAKDOWN_KEY: u128 = 8;
                const MAX_TRIGGER_VALUE: u128 = 5;
                const NUM_MULTI_BITS: u32 = 3;
                const MAX_MATCH_KEY: u128 = 3;

                let world = TestWorld::new().await;
                let mut rng = thread_rng();

                let records = (0..BATCHSIZE)
                    .map(|_| {
                        ipa_test_input!(
                            [{
                                    match_key: rng.gen_range(0..MAX_MATCH_KEY),
                                    is_trigger_report: rng.gen::<u32>(),
                                    breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                                    trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE)
                            }];
                            (Fp32BitPrime, MatchKey, BreakdownKey)
                        )
                        .remove(0)
                    })
                    .collect::<Vec<_>>();

                let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> =
                    world
                        .semi_honest(records, |ctx, input_rows| async move {
                            ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
                                ctx,
                                &input_rows,
                                PER_USER_CAP,
                                MAX_BREAKDOWN_KEY,
                                NUM_MULTI_BITS,
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
