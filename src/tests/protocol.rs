#![cfg(all(feature = "shuttle", test))]

use crate::{
    ff::Fp32BitPrime,
    helpers::query::IpaQueryConfig,
    ipa_test_input,
    protocol::{ipa::ipa, BreakdownKey, MatchKey},
    rand::{thread_rng, Rng},
    test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
};
use std::num::NonZeroU32;

const BATCHSIZE: usize = 5;
const PER_USER_CAP: u32 = 10;
const MAX_BREAKDOWN_KEY: u32 = 8;
const ATTRIBUTION_WINDOW_SECONDS: Option<NonZeroU32> = NonZeroU32::new(86_400);
const MAX_TRIGGER_VALUE: u32 = 5;
const NUM_MULTI_BITS: u32 = 3;
const MAX_MATCH_KEY: u128 = 3;

/// The type of the generated inputs.
type Input = Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>>;
/// ... and the reconstructed output of `ipa()`.
type Output = Vec<Fp32BitPrime>;

fn inputs() -> Input {
    let mut rng = thread_rng();
    (0..BATCHSIZE)
        .map(|_| {
            ipa_test_input!(
                {
                    timestamp: 0,
                    match_key: rng.gen_range(0..MAX_MATCH_KEY),
                    is_trigger_report: rng.gen::<u32>(),
                    breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                    trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE),
                };
                (Fp32BitPrime, MatchKey, BreakdownKey)
            )
        })
        .collect::<Vec<_>>()
}

fn config() -> IpaQueryConfig {
    IpaQueryConfig::new(
        PER_USER_CAP,
        MAX_BREAKDOWN_KEY,
        ATTRIBUTION_WINDOW_SECONDS.unwrap().get(),
        NUM_MULTI_BITS,
    )
}

#[test]
fn semi_honest() {
    shuttle::check_random(
        move || {
            shuttle::future::block_on(async {
                let world = TestWorld::default();
                let result: Output = world
                    .semi_honest(inputs().into_iter(), |ctx, input_rows| async move {
                        ipa(ctx, &input_rows, config()).await.unwrap()
                    })
                    .await
                    .reconstruct();
                assert_eq!(MAX_BREAKDOWN_KEY, u32::try_from(result.len()).unwrap());
            });
        },
        10,
    );
}

#[test]
fn malicious() {
    shuttle::check_random(
        move || {
            shuttle::future::block_on(async {
                let world = TestWorld::default();
                let result: Output = world
                    .malicious(inputs().into_iter(), |ctx, input_rows| async move {
                        ipa(ctx, &input_rows, config()).await.unwrap()
                    })
                    .await
                    .reconstruct();
                assert_eq!(MAX_BREAKDOWN_KEY, u32::try_from(result.len()).unwrap());
            });
        },
        4,
    );
}
