use std::{array, num::NonZeroUsize};

use futures::{future::join3, stream, StreamExt};
use ipa_step::StepNarrow;
use rand::distributions::{Distribution, Standard};

use crate::{
    ff::{Field, U128Conversions},
    helpers::{GatewayConfig, TotalRecords},
    protocol::{
        basics::SecureMul,
        context::{Context, SemiHonestContext},
        step::{ProtocolStep, TestExecutionStep as Step},
        Gate, RecordId,
    },
    rand::thread_rng,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, IntoShares},
    seq_join::seq_join,
    test_fixture::{ReconstructArr, TestWorld, TestWorldConfig},
    utils::array::zip3,
};

pub struct Inputs<F: Field + FieldSimd<N>, const N: usize> {
    a: Replicated<F, N>,
    b: Vec<Replicated<F, N>>,
}

impl<F: Field + FieldSimd<N>, const N: usize> Inputs<F, N> {
    fn new(a: Replicated<F, N>, b: Vec<Replicated<F, N>>) -> Self {
        Self { a, b }
    }
}

/// Generates test data for the arithmetic ciruit benchmark.
///
/// # Panics
/// On functional errors, since this is a benchmark.
#[must_use]
pub fn arithmetic_setup<F, const N: usize>(width: u32, depth: u16) -> [Vec<Inputs<F, N>>; 3]
where
    F: Field + FieldSimd<N>,
    Standard: Distribution<F>,
{
    let mut rng = thread_rng();
    let mut data = array::from_fn(|_| Vec::with_capacity(width as usize / N));
    for _ in 0..(width / u32::try_from(N).unwrap()) {
        let [a0, a1, a2] = [F::ONE; N].share_with(&mut rng);
        let mut b0 = Vec::with_capacity(depth as usize);
        let mut b1 = Vec::with_capacity(depth as usize);
        let mut b2 = Vec::with_capacity(depth as usize);
        for _ in 0..(depth as usize) {
            let [s0, s1, s2] = [F::ONE; N].share_with(&mut rng);
            b0.push(s0);
            b1.push(s1);
            b2.push(s2);
        }
        data[0].push(Inputs::new(a0, b0));
        data[1].push(Inputs::new(a1, b1));
        data[2].push(Inputs::new(a2, b2));
    }
    data
}

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// On functional errors, since this is a benchmark.
pub async fn arithmetic<F, const N: usize>(
    width: u32,
    depth: u16,
    active_work: usize,
    input_data: [Vec<Inputs<F, N>>; 3],
) where
    F: Field + FieldSimd<N> + U128Conversions,
    for<'a> Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
    [F; N]: IntoShares<Replicated<F, N>>,
    Standard: Distribution<F>,
{
    let active = NonZeroUsize::new(active_work).unwrap();
    let config = TestWorldConfig {
        gateway_config: GatewayConfig {
            active,
            ..Default::default()
        },
        initial_gate: Some(Gate::default().narrow(&ProtocolStep::Test)),
        ..Default::default()
    };
    let world = TestWorld::new_with(config);

    // Re-use contexts for the entire execution because record identifiers are contiguous.
    let contexts = world.contexts();

    let [fut0, fut1, fut2] = zip3(contexts, input_data).map(|(ctx, col_data)| {
        // Setting TotalRecords::Indeterminate causes OrderingSender to make data available to
        // the channel immediately, instead of doing so only after active_work records have
        // accumulated. This gives the best performance for vectorized operation.
        let ctx = ctx.set_total_records(TotalRecords::Indeterminate);
        seq_join(
            active,
            stream::iter((0..(width / u32::try_from(N).unwrap())).zip(col_data)).map(
                move |(record, Inputs { a, b })| {
                    circuit(ctx.clone(), RecordId::from(record), depth, a, b)
                },
            ),
        )
        .collect::<Vec<_>>()
    });

    let (res0, res1, res2) = join3(fut0, fut1, fut2).await;

    let mut sum = 0;
    for line in res0.into_iter().zip(res1).zip(res2) {
        let ((s0, s1), s2) = line;
        for col_sum in [s0, s1, s2].reconstruct_arr() {
            sum += col_sum.as_u128();
        }
    }

    assert_eq!(sum, u128::from(width));
}

async fn circuit<'a, F, const N: usize>(
    ctx: SemiHonestContext<'a>,
    record_id: RecordId,
    depth: u16,
    mut a: Replicated<F, N>,
    b: Vec<Replicated<F, N>>,
) -> Replicated<F, N>
where
    F: Field + FieldSimd<N>,
    Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
{
    assert_eq!(b.len(), usize::from(depth));
    for (stripe_ix, stripe) in b.iter().enumerate() {
        let stripe_ctx = ctx.narrow(&Step::Iter(stripe_ix));
        a = a.multiply(stripe, stripe_ctx, record_id).await.unwrap();
    }

    a
}
