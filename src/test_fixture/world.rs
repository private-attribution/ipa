use crate::rand::thread_rng;
use async_trait::async_trait;
use futures::{future::join_all, Future};
use rand::{distributions::Standard, prelude::Distribution};

use crate::sync::atomic::{AtomicUsize, Ordering};
use crate::test_fixture::metrics::MetricsHandle;
use crate::{
    ff::Field,
    helpers::{
        messaging::{Gateway, GatewayConfig},
        Role, SendBufferConfig,
    },
    protocol::{
        context::{
            Context, MaliciousContext, SemiHonestContext, UpgradeContext, UpgradeToMalicious,
        },
        malicious::MaliciousValidator,
        prss::Endpoint as PrssEndpoint,
    },
    secret_sharing::replicated::malicious::DowngradeMalicious,
    test_fixture::{logging, make_participants},
};

use std::io::stdout;

use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::{fmt::Debug, iter::zip, sync::Arc};

use crate::helpers::network::Network;
use crate::helpers::RoleAssignment;
use crate::protocol::{QueryId, Substep};
use crate::secret_sharing::IntoShares;
use crate::telemetry::stats::Metrics;
use crate::telemetry::StepStatsCsvExporter;
use crate::test_fixture::transport::InMemoryNetwork;
use tracing::Level;

use super::{sharing::ValidateMalicious, Reconstruct};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
pub struct TestWorld {
    gateways: ManuallyDrop<[Gateway; 3]>,
    participants: [PrssEndpoint; 3],
    executions: AtomicUsize,
    metrics_handle: MetricsHandle,
    joined: AtomicBool,
    _network: InMemoryNetwork,
}

#[derive(Copy, Clone)]
pub struct TestWorldConfig {
    pub gateway_config: GatewayConfig,
    /// Level for metrics span. If set to the tracing level or above (controlled by `RUST_LOG` and
    /// `logging` module) will result in metrics being recorded by this test world instance.
    /// recorded by this test world unless `RUST_LOG` for this crate is set to
    pub metrics_level: Level,
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            gateway_config: GatewayConfig {
                send_buffer_config: SendBufferConfig {
                    // This value set to 1 effectively means no buffering. This is the desired mode
                    // for unit tests to drive them to completion as fast as possible.
                    items_in_batch: NonZeroUsize::new(1).unwrap(),

                    // How many messages can be sent in parallel. This value is picked arbitrarily as
                    // most unit tests don't send more than this value, so the setup does not have to
                    // be annoying. `items_in_batch` * `batch_count` defines the total capacity for
                    // send buffer. Increasing this value does not really impact the latency for tests
                    // because they flush the data to network once they've accumulated at least
                    // `items_in_batch` elements. Ofc setting it to some absurdly large value is going
                    // to be problematic from memory perspective.
                    batch_count: NonZeroUsize::new(40).unwrap(),
                },
                send_outstanding: 16,
                recv_outstanding: 16,
            },
            // Disable metrics by default because `logging` only enables `Level::INFO` spans.
            // Can be overridden by setting `RUST_LOG` environment variable to match this level.
            metrics_level: Level::DEBUG,
        }
    }
}

impl TestWorldConfig {
    pub fn enable_metrics(&mut self) -> &mut Self {
        self.metrics_level = Level::INFO;
        self
    }
}

impl TestWorld {
    /// Creates a new `TestWorld` instance using the provided `config`.
    /// # Panics
    /// Never.
    pub async fn new_with(config: TestWorldConfig) -> TestWorld {
        logging::setup();

        let metrics_handle = MetricsHandle::new(config.metrics_level);
        let participants = make_participants();
        let network = InMemoryNetwork::default();
        let role_assignment = RoleAssignment::new(network.helper_identities());

        let gateways = join_all(network.transports.iter().enumerate().map(|(i, transport)| {
            let role_assignment = role_assignment.clone();
            async move {
                // simple role assignment, based on transport index
                let role = Role::all()[i];
                let network = Network::new(Arc::downgrade(transport), QueryId, role_assignment);
                Gateway::new(role, network, config.gateway_config).await
            }
        }))
        .await
        .try_into()
        .unwrap();

        TestWorld {
            gateways: ManuallyDrop::new(gateways),
            participants,
            executions: AtomicUsize::new(0),
            metrics_handle,
            joined: AtomicBool::new(false),
            _network: network,
        }
    }

    /// # Panics
    /// Never.
    pub async fn new() -> TestWorld {
        let config = TestWorldConfig::default();
        Self::new_with(config).await
    }

    /// Creates protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts<F: Field>(&self) -> [SemiHonestContext<'_, F>; 3] {
        let execution = self.executions.fetch_add(1, Ordering::Release);
        zip(&self.participants, &*self.gateways)
            .map(|(participant, gateway)| {
                SemiHonestContext::new(participant, gateway)
                    .narrow(&Self::execution_step(execution))
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> Metrics {
        self.metrics_handle.snapshot()
    }

    #[must_use]
    pub fn execution_step(execution: usize) -> impl Substep {
        format!("run-{execution}")
    }

    pub fn gateway(&self, role: Role) -> &Gateway {
        &self.gateways[role]
    }

    #[cfg(not(feature = "shuttle"))]
    pub async fn join(mut self) {
        // SAFETY: self is consumed by this method, so nobody can access gateways field after
        // calling this method.
        // joined flag is used inside the destructor to avoid double-free
        if !self.joined.swap(true, Ordering::Release) {
            let gateways = unsafe { ManuallyDrop::take(&mut self.gateways) };
            for gateway in gateways {
                gateway.join().await;
            }
        }
    }
}

impl Drop for TestWorld {
    fn drop(&mut self) {
        if !self.joined.load(Ordering::Acquire) {
            unsafe { ManuallyDrop::drop(&mut self.gateways) };
        }

        if tracing::span_enabled!(Level::DEBUG) {
            let metrics = self.metrics_handle.snapshot();
            metrics.export(&mut stdout()).unwrap();
        }
    }
}

#[async_trait]
pub trait Runner<I, A, F> {
    async fn semi_honest<'a, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        F: Field,
        O: Send + Debug,
        H: Fn(SemiHonestContext<'a, F>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
        Standard: Distribution<F>;

    async fn malicious<'a, O, M, H, R, P>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        for<'u> UpgradeContext<'u, F>: UpgradeToMalicious<A, M>,
        F: Field,
        O: Send + Debug,
        M: Send,
        H: Fn(MaliciousContext<'a, F>, M) -> R + Send + Sync,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Clone + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>;
}

/// Separate a length-3 array of tuples (T, U, V) into a tuple of length-3
/// arrays of T's, U's, and V's.
fn split_array_of_tuples<T, U, V>(v: [(T, U, V); 3]) -> ([T; 3], [U; 3], [V; 3]) {
    let [v0, v1, v2] = v;
    ([v0.0, v1.0, v2.0], [v0.1, v1.1, v2.1], [v0.2, v1.2, v2.2])
}

#[async_trait]
impl<I, A, F> Runner<I, A, F> for TestWorld
where
    I: 'static + IntoShares<A> + Send,
    A: Send,
    F: Field,
{
    async fn semi_honest<'a, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        O: Send + Debug,
        H: Fn(SemiHonestContext<'a, F>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
        Standard: Distribution<F>,
    {
        let contexts = self.contexts();
        let input_shares = {
            let mut rng = thread_rng();
            input.share_with(&mut rng)
        };

        let output =
            join_all(zip(contexts, input_shares).map(|(ctx, shares)| helper_fn(ctx, shares))).await;
        <[_; 3]>::try_from(output).unwrap()
    }

    async fn malicious<'a, O, M, H, R, P>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        for<'u> UpgradeContext<'u, F>: UpgradeToMalicious<A, M>,
        O: Send + Debug,
        M: Send,
        H: Fn(MaliciousContext<'a, F>, M) -> R + Send + Sync,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Clone + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>,
    {
        let (m_results, r_shares, output) = split_array_of_tuples(
            self.semi_honest(input, |ctx, share| async {
                let v = MaliciousValidator::new(ctx);
                let m_share = v.context().upgrade(share).await.unwrap();
                let m_result = helper_fn(v.context(), m_share).await;
                let m_result_clone = m_result.clone();
                let r_share = v.r_share().clone();
                let output = v.validate(m_result_clone).await.unwrap();
                (m_result, r_share, output)
            })
            .await,
        );

        // Sanity check that rx = r * x at the output (it should not be possible
        // for this to fail if the distributed validation protocol passed).
        let r = r_shares.reconstruct();
        m_results.validate(r);

        output
    }
}
