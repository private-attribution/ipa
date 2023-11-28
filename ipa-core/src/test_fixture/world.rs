use std::{fmt::Debug, io::stdout, iter::zip};

use async_trait::async_trait;
use futures::{future::join_all, Future};
use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng};
use rand_core::{RngCore, SeedableRng};
use tracing::{Instrument, Level, Span};

use crate::{
    helpers::{Gateway, GatewayConfig, InMemoryNetwork, Role, RoleAssignment},
    protocol::{
        context::{
            Context, MaliciousContext, SemiHonestContext, UpgradableContext, UpgradeContext,
            UpgradeToMalicious, UpgradedContext, UpgradedMaliciousContext, Validator,
        },
        prss::Endpoint as PrssEndpoint,
        QueryId,
    },
    rand::thread_rng,
    secret_sharing::{
        replicated::malicious::{DowngradeMalicious, ExtendableField},
        IntoShares,
    },
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    telemetry::{stats::Metrics, StepStatsCsvExporter},
    test_fixture::{
        logging, make_participants, metrics::MetricsHandle, sharing::ValidateMalicious, Reconstruct,
    },
};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
pub struct TestWorld {
    gateways: [Gateway; 3],
    participants: [PrssEndpoint; 3],
    executions: AtomicUsize,
    metrics_handle: MetricsHandle,
    _network: InMemoryNetwork,
}

#[derive(Clone)]
pub struct TestWorldConfig {
    pub gateway_config: GatewayConfig,
    /// Level for metrics span. If set to the tracing level or above (controlled by `RUST_LOG` and
    /// `logging` module) will result in metrics being recorded by this test world instance.
    /// recorded by this test world unless `RUST_LOG` for this crate is set to
    pub metrics_level: Level,
    /// Assignment of roles to helpers. If `None`, a default assignment will be used.
    pub role_assignment: Option<RoleAssignment>,
    /// Seed for random generators used in PRSS
    pub seed: u64,
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            // Only keep a small amount of active work on hand.
            gateway_config: GatewayConfig::new(16),
            // Disable metrics by default because `logging` only enables `Level::INFO` spans.
            // Can be overridden by setting `RUST_LOG` environment variable to match this level.
            metrics_level: Level::DEBUG,
            role_assignment: None,
            seed: thread_rng().next_u64(),
        }
    }
}

impl TestWorldConfig {
    #[must_use]
    pub fn enable_metrics(mut self) -> Self {
        self.metrics_level = Level::INFO;
        self
    }

    #[must_use]
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
}

impl Default for TestWorld {
    fn default() -> Self {
        Self::new_with(TestWorldConfig::default())
    }
}

impl TestWorld {
    /// Creates a new `TestWorld` instance using the provided `config`.
    /// # Panics
    /// Never.
    #[must_use]
    pub fn new_with(config: TestWorldConfig) -> Self {
        logging::setup();

        let metrics_handle = MetricsHandle::new(config.metrics_level);
        let participants = make_participants(&mut StdRng::seed_from_u64(config.seed));
        let network = InMemoryNetwork::default();
        let role_assignment = config
            .role_assignment
            .unwrap_or_else(|| RoleAssignment::new(network.helper_identities()));

        let mut gateways = [None, None, None];
        for i in 0..3 {
            let transport = &network.transports[i];
            let role_assignment = role_assignment.clone();
            let gateway = Gateway::new(
                QueryId,
                config.gateway_config,
                role_assignment,
                Arc::downgrade(transport),
            );
            let role = gateway.role();
            gateways[role] = Some(gateway);
        }
        let gateways = gateways.map(Option::unwrap);

        TestWorld {
            gateways,
            participants,
            executions: AtomicUsize::new(0),
            metrics_handle,
            _network: network,
        }
    }

    /// Creates protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts(&self) -> [SemiHonestContext<'_>; 3] {
        let execution = self.executions.fetch_add(1, Ordering::Relaxed);
        zip(&self.participants, &self.gateways)
            .map(|(participant, gateway)| {
                SemiHonestContext::new(participant, gateway)
                    .narrow(&Self::execution_step(execution))
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Creates malicious protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn malicious_contexts(&self) -> [MaliciousContext<'_>; 3] {
        let execution = self.executions.fetch_add(1, Ordering::Relaxed);
        zip(&self.participants, &self.gateways)
            .map(|(participant, gateway)| {
                MaliciousContext::new(participant, gateway).narrow(&Self::execution_step(execution))
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
    pub fn execution_step(execution: usize) -> String {
        format!("run-{execution}")
    }

    pub fn gateway(&self, role: Role) -> &Gateway {
        &self.gateways[role]
    }

    /// See `Runner` below.
    async fn run_either<'a, C, I, A, O, H, R>(
        contexts: [C; 3],
        span: Span,
        input: I,
        helper_fn: H,
    ) -> [O; 3]
    where
        C: UpgradableContext,
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(C, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        let input_shares = input.share_with(&mut thread_rng());
        #[allow(clippy::disallowed_methods)] // It's just 3 items.
        let output =
            join_all(zip(contexts, input_shares).map(|(ctx, shares)| helper_fn(ctx, shares)))
                .instrument(span)
                .await;
        <[_; 3]>::try_from(output).unwrap()
    }
}

impl Drop for TestWorld {
    fn drop(&mut self) {
        if tracing::span_enabled!(Level::DEBUG) {
            let metrics = self.metrics_handle.snapshot();
            metrics.export(&mut stdout()).unwrap();
        }
    }
}

#[async_trait]
pub trait Runner {
    /// Run with a context that can be upgraded, but is only good for semi-honest.
    async fn semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(SemiHonestContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send;

    /// Run with a context that can be upgraded to malicious.
    async fn malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(MaliciousContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send;

    /// Run with a context that has already been upgraded to malicious.
    async fn upgraded_malicious<'a, F, I, A, M, O, H, R, P>(
        &'a self,
        input: I,
        helper_fn: H,
    ) -> [O; 3]
    where
        F: ExtendableField,
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        for<'u> UpgradeContext<'u, UpgradedMaliciousContext<'a, F>, F>:
            UpgradeToMalicious<'u, A, M>,
        O: Send + Debug,
        M: Send + 'static,
        H: Fn(UpgradedMaliciousContext<'a, F>, M) -> R + Send + Sync,
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
impl Runner for TestWorld {
    async fn semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(SemiHonestContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        Self::run_either(
            self.contexts(),
            self.metrics_handle.span(),
            input,
            helper_fn,
        )
        .await
    }

    async fn malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(MaliciousContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        Self::run_either(
            self.malicious_contexts(),
            self.metrics_handle.span(),
            input,
            helper_fn,
        )
        .await
    }

    async fn upgraded_malicious<'a, F, I, A, M, O, H, R, P>(
        &'a self,
        input: I,
        helper_fn: H,
    ) -> [O; 3]
    where
        F: ExtendableField,
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        for<'u> UpgradeContext<'u, UpgradedMaliciousContext<'a, F>, F>:
            UpgradeToMalicious<'u, A, M>,
        O: Send + Debug,
        M: Send + 'static,
        H: Fn(UpgradedMaliciousContext<'a, F>, M) -> R + Send + Sync,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Clone + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>,
    {
        let (m_results, r_shares, output) = split_array_of_tuples(
            self.malicious(input, |ctx, share| async {
                let v = ctx.validator();
                let m_ctx = v.context();
                let m_share = m_ctx.upgrade(share).await.unwrap();
                let m_result = helper_fn(m_ctx, m_share).await;
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
