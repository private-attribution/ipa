use std::{array::from_fn, borrow::Borrow, fmt::Debug, io::stdout, iter::zip, marker::PhantomData};

use async_trait::async_trait;
use futures::{future::join_all, Future};
use futures_util::{stream::FuturesOrdered, StreamExt};
use ipa_macros::Step;
use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng, thread_rng};
use rand_core::{RngCore, SeedableRng};
use tracing::{Instrument, Level, Span};

use crate::{
    helpers::{
        Gateway, GatewayConfig, HelperIdentity, InMemoryMpcNetwork, InMemoryShardNetwork,
        InMemoryTransport, Role, RoleAssignment, Transport,
    },
    protocol::{
        context::{
            Context, MaliciousContext, SemiHonestContext, ShardedSemiHonestContext,
            UpgradableContext, UpgradeContext, UpgradeToMalicious, UpgradedContext,
            UpgradedMaliciousContext, Validator,
        },
        prss::Endpoint as PrssEndpoint,
        QueryId,
    },
    secret_sharing::{
        replicated::malicious::{DowngradeMalicious, ExtendableField},
        IntoShares,
    },
    sharding::{NotSharded, ShardBinding, ShardIndex, Sharded},
    sync::atomic::{AtomicUsize, Ordering},
    telemetry::{stats::Metrics, StepStatsCsvExporter},
    test_fixture::{
        logging, make_participants, metrics::MetricsHandle, sharing::ValidateMalicious, Reconstruct,
    },
};

// This is used by the metrics tests in `protocol::context`. It otherwise would/should not be pub.
#[derive(Step)]
pub enum TestExecutionStep {
    /// Provides a unique per-iteration context in tests.
    #[dynamic(1024)]
    Iter(usize),
}

pub trait ShardingScheme {
    type Container<A>;
    /// This type reflects how this scheme binds to [`ShardBinding`] interface used in [`Context`].
    /// Single shard systems do not use sharding capabilities, so the point of shard index is moot
    /// Multi-shard system must inform MPC circuits about shard they operate on and total number
    /// of shards within the system.
    ///
    /// See [`NotSharded`], [`WithShards`] and [`ShardBinding`]
    type ShardBinding: ShardBinding;
    /// Number of shards used inside the test world.
    const SHARDS: usize;

    /// Creates a binding for the given shard id. For non-sharded systems, this is a no-op.
    fn bind_shard(shard_id: ShardIndex) -> Self::ShardBinding;
}

/// Helper trait to parametrize [`Runner`] trait based on the sharding scheme chosen. The whole
/// purpose of it is to be able to say for sharded runs, the input must be in a form of a [`Vec`]
pub trait RunnerInput<S: ShardingScheme, A: Send>: Send {
    fn share(self) -> [S::Container<A>; 3];
}

/// This indicates how many shards need to be created in test environment.
pub struct WithShards<const SHARDS: usize>;

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
///
/// Test environment is parametrized by [`S`] that indicates the sharding scheme used. By default,
/// there is no sharding involved and the system operates as a single MPC circuit.
///
/// To construct a sharded environment, use [`TestWorld::<WithShards>::with_shards`] method.
pub struct TestWorld<S: ShardingScheme = NotSharded> {
    shards: Box<[ShardWorld<S::ShardBinding>]>,
    metrics_handle: MetricsHandle,
    _shard_network: InMemoryShardNetwork,
    _phantom: PhantomData<S>,
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

impl ShardingScheme for NotSharded {
    /// For single-sharded worlds, there is no need to have the ability to distribute data across
    /// shards. Any MPC circuit can take even a single share as input and produce meaningful outcome.
    type Container<A> = A;
    type ShardBinding = Self;
    const SHARDS: usize = 1;

    fn bind_shard(shard_id: ShardIndex) -> Self::ShardBinding {
        assert_eq!(
            ShardIndex::FIRST,
            shard_id,
            "Only one shard is allowed for non-sharded MPC"
        );

        Self
    }
}

impl<const N: usize> ShardingScheme for WithShards<N> {
    /// The easiest way to distribute data across shards is to take a collection with a known size
    /// as input.
    type Container<A> = Vec<A>;
    type ShardBinding = Sharded;
    const SHARDS: usize = N;

    fn bind_shard(shard_id: ShardIndex) -> Self::ShardBinding {
        let shard_count = ShardIndex::try_from(N).unwrap();
        assert!(
            shard_id < shard_count,
            "Maximum {N} shards is allowed, {shard_id} is greater than this number"
        );

        Self::ShardBinding {
            shard_id,
            shard_count,
        }
    }
}

impl<const SHARDS: usize> WithShards<SHARDS> {
    /// Partitions the input vector into a smaller vectors where each vector holds the input
    /// for a single shard.
    ///
    /// It uses Round-robin strategy to distribute [`A`] across [`SHARDS`]
    #[must_use]
    pub fn shard<A>(input: Vec<A>) -> [Vec<A>; SHARDS] {
        let mut r: [_; SHARDS] = from_fn(|_| Vec::new());
        for (i, share) in input.into_iter().enumerate() {
            r[i % SHARDS].push(share);
        }

        r
    }
}

impl Default for TestWorld {
    fn default() -> Self {
        Self::new_with(TestWorldConfig::default())
    }
}

impl<const SHARDS: usize> TestWorld<WithShards<SHARDS>> {
    /// For backward compatibility, this method must have a different name than [`non_sharded`] method.
    ///
    /// [`non_sharded`]: TestWorld::<NotSharded>::new_with
    #[must_use]
    pub fn with_shards<B: Borrow<TestWorldConfig>>(config: B) -> Self {
        Self::with_config(config.borrow())
    }

    fn shards(&self) -> [&ShardWorld<Sharded>; SHARDS] {
        self.shards
            .iter()
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }
}

/// Backward-compatible API for tests that don't use sharding.
impl TestWorld<NotSharded> {
    /// Creates a new `TestWorld` instance using the provided `config`.
    /// # Panics
    /// Never.
    #[must_use]
    pub fn new_with<B: Borrow<TestWorldConfig>>(config: B) -> Self {
        Self::with_config(config.borrow())
    }

    /// Creates protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts(&self) -> [SemiHonestContext<'_>; 3] {
        self.shards[0].contexts()
    }

    /// Creates malicious protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn malicious_contexts(&self) -> [MaliciousContext<'_>; 3] {
        self.shards[0].malicious_contexts()
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> Metrics {
        self.metrics_handle.snapshot()
    }

    #[must_use]
    pub fn gateway(&self, role: Role) -> &Gateway {
        &self.shards[0].gateways[role]
    }
}

impl<S: ShardingScheme> Drop for TestWorld<S> {
    fn drop(&mut self) {
        if tracing::span_enabled!(Level::DEBUG) || cfg!(feature = "step-trace") {
            let metrics = self.metrics_handle.snapshot();
            metrics.export(&mut stdout()).unwrap();
        }
    }
}

impl<S: ShardingScheme> TestWorld<S> {
    /// Creates a new environment with the number of shards specified inside [`S`].
    ///
    /// ## Panics
    /// If more than [`std::u32::MAX`] shards are requested.
    #[must_use]
    pub fn with_config(config: &TestWorldConfig) -> Self {
        logging::setup();
        // Print to stdout so that it appears in test runs only on failure.
        // scripts/collect_steps.py must be updated if the message text changes.
        println!("TestWorld random seed {seed}", seed = config.seed);

        let shard_count = ShardIndex::try_from(S::SHARDS).unwrap();
        let shard_network = InMemoryShardNetwork::with_shards(shard_count);

        let shards = shard_count
            .iter()
            .map(|shard| {
                ShardWorld::new(
                    S::bind_shard(shard),
                    config,
                    u64::from(shard),
                    shard_network.shard_transports(shard),
                )
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            shards,
            metrics_handle: MetricsHandle::new(config.metrics_level),
            _shard_network: shard_network,
            _phantom: PhantomData,
        }
    }
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

    #[must_use]
    pub fn role_assignment(&self) -> &RoleAssignment {
        const DEFAULT_ASSIGNMENT: RoleAssignment = RoleAssignment::new([
            HelperIdentity::ONE,
            HelperIdentity::TWO,
            HelperIdentity::THREE,
        ]);
        self.role_assignment.as_ref().unwrap_or(&DEFAULT_ASSIGNMENT)
    }
}

impl<I: IntoShares<A> + Send, A: Send> RunnerInput<NotSharded, A> for I {
    fn share(self) -> [A; 3] {
        I::share(self)
    }
}

impl<const SHARDS: usize, I, A> RunnerInput<WithShards<SHARDS>, A> for I
where
    I: IntoShares<Vec<A>> + Send,
    A: Send,
{
    fn share(self) -> [Vec<A>; 3] {
        I::share(self)
    }
}

#[async_trait]
pub trait Runner<S: ShardingScheme> {
    /// This could be also derived from [`S`], but maybe that's too much for that trait.
    type SemiHonestContext<'ctx>: Context;

    /// Run with a context that can be upgraded, but is only good for semi-honest.
    async fn semi_honest<'a, I, A, O, H, R>(
        &'a self,
        input: I,
        helper_fn: H,
    ) -> S::Container<[O; 3]>
    where
        I: RunnerInput<S, A>,
        A: Send,
        O: Send + Debug,
        H: Fn(Self::SemiHonestContext<'a>, S::Container<A>) -> R + Send + Sync,
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
impl<const SHARDS: usize> Runner<WithShards<SHARDS>> for TestWorld<WithShards<SHARDS>> {
    type SemiHonestContext<'ctx> = ShardedSemiHonestContext<'ctx>;
    async fn semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> Vec<[O; 3]>
    where
        I: RunnerInput<WithShards<SHARDS>, A>,
        A: Send,
        O: Send + Debug,
        H: Fn(
                Self::SemiHonestContext<'a>,
                <WithShards<SHARDS> as ShardingScheme>::Container<A>,
            ) -> R
            + Send
            + Sync,
        R: Future<Output = O> + Send,
    {
        let shards = self.shards();
        let [h1, h2, h3] = input.share().map(WithShards::<SHARDS>::shard);

        // No clippy, you're wrong, it is not redundant, it allows shard_fn to be `Copy`
        #[allow(clippy::redundant_closure)]
        let shard_fn = |ctx, input| helper_fn(ctx, input);
        zip(shards.into_iter(), zip(zip(h1, h2), h3))
            .map(|(shard, ((h1, h2), h3))| {
                ShardWorld::<Sharded>::run_either(
                    shard.contexts(),
                    self.metrics_handle.span(),
                    [h1, h2, h3],
                    shard_fn,
                )
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
    }

    async fn malicious<'a, I, A, O, H, R>(&'a self, _input: I, _helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(MaliciousContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        unimplemented!()
    }

    async fn upgraded_malicious<'a, F, I, A, M, O, H, R, P>(
        &'a self,
        _input: I,
        _helper_fn: H,
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
        unimplemented!()
    }
}

#[async_trait]
impl Runner<NotSharded> for TestWorld<NotSharded> {
    type SemiHonestContext<'ctx> = SemiHonestContext<'ctx>;

    async fn semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: RunnerInput<NotSharded, A>,
        A: Send,
        O: Send + Debug,
        H: Fn(Self::SemiHonestContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        ShardWorld::<NotSharded>::run_either(
            self.contexts(),
            self.metrics_handle.span(),
            input.share(),
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
        ShardWorld::<NotSharded>::run_either(
            self.malicious_contexts(),
            self.metrics_handle.span(),
            input.share(),
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

struct ShardWorld<B: ShardBinding> {
    shard_info: B,
    gateways: [Gateway; 3],
    participants: [PrssEndpoint; 3],
    executions: AtomicUsize,
    // It will be used once Gateway knows how to route shard traffic
    _shard_connections: [InMemoryTransport<ShardIndex>; 3],
    _mpc_network: InMemoryMpcNetwork,
    _phantom: PhantomData<B>,
}

impl<B: ShardBinding> ShardWorld<B> {
    pub fn new(
        shard_info: B,
        config: &TestWorldConfig,
        shard_seed: u64,
        transports: [InMemoryTransport<ShardIndex>; 3],
    ) -> Self {
        // todo: B -> seed
        let participants = make_participants(&mut StdRng::seed_from_u64(config.seed + shard_seed));
        let network = InMemoryMpcNetwork::default();

        let mut gateways: [_; 3] = network
            .transports()
            .iter()
            .zip(transports.iter())
            .map(|(mpc, shard)| {
                Gateway::new(
                    QueryId,
                    config.gateway_config,
                    config.role_assignment().clone(),
                    Transport::clone_ref(mpc),
                    Transport::clone_ref(shard),
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();

        // The name for `g` is too complicated and depends on features enabled
        #[allow(clippy::redundant_closure_for_method_calls)]
        gateways.sort_by_key(|g| g.role());

        ShardWorld {
            shard_info,
            gateways,
            participants,
            executions: AtomicUsize::default(),
            _shard_connections: transports,
            _mpc_network: network,
            _phantom: PhantomData,
        }
    }

    /// See `Runner` above.
    async fn run_either<'a, C, A, O, H, R>(
        contexts: [C; 3],
        span: Span,
        input_shares: [A; 3],
        helper_fn: H,
    ) -> [O; 3]
    where
        C: UpgradableContext,
        A: Send,
        O: Send + Debug,
        H: Fn(C, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        #[allow(clippy::disallowed_methods)] // It's just 3 items.
        let output = join_all(zip(contexts, input_shares).map(|(ctx, shares)| {
            let role = ctx.role();
            helper_fn(ctx, shares).instrument(tracing::trace_span!("", role = ?role))
        }))
        .instrument(span)
        .await;
        <[_; 3]>::try_from(output).unwrap()
    }

    /// Creates protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts(&self) -> [SemiHonestContext<'_, B>; 3] {
        let step = TestExecutionStep::Iter(self.executions.fetch_add(1, Ordering::Relaxed));
        zip(&self.participants, &self.gateways)
            .map(|(participant, gateway)| {
                SemiHonestContext::new_complete(participant, gateway, self.shard_info.clone())
                    .narrow(&step)
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
                MaliciousContext::new(participant, gateway)
                    .narrow(&TestExecutionStep::Iter(execution))
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use crate::{
        ff::{boolean_array::BA3, U128Conversions},
        protocol::{context::Context, prss::SharedRandomness},
        sharding::ShardConfiguration,
        test_executor::run,
        test_fixture::{world::WithShards, Reconstruct, Runner, TestWorld, TestWorldConfig},
    };

    #[test]
    fn two_shards() {
        run(|| async {
            let world: TestWorld<WithShards<2>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![BA3::truncate_from(0_u32), BA3::truncate_from(1_u32)];
            let r = world
                .semi_honest(input.clone().into_iter(), |ctx, input| async move {
                    assert_eq!(2_usize, usize::from(ctx.shard_count()));
                    input
                })
                .await
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            assert_eq!(input, r);
        });
    }

    #[test]
    fn small_input_size() {
        run(|| async {
            let world: TestWorld<WithShards<10>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![BA3::truncate_from(0_u32), BA3::truncate_from(1_u32)];
            let r = world
                .semi_honest(input.clone().into_iter(), |_, input| async move { input })
                .await
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            assert_eq!(input, r);
        });
    }

    #[test]
    fn unique_prss_per_shard() {
        run(|| async {
            let world: TestWorld<WithShards<3>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![(), (), ()];
            let duplicates = Arc::new(Mutex::new(HashMap::new()));
            let _ = world
                .semi_honest(input.into_iter(), |ctx, _| {
                    let duplicates = Arc::clone(&duplicates);
                    async move {
                        let (l, r): (u128, u128) = ctx.prss().generate(0_u32);
                        let mut duplicates = duplicates.lock().unwrap();
                        let e = duplicates.entry(ctx.role()).or_insert_with(HashSet::new);
                        assert!(e.insert(l) & e.insert(r), "{:?}: duplicate values generated on shard {}: {l}/{r}: previously generated: {e:?}", ctx.role(), ctx.shard_id());
                    }
                })
                .await.into_iter().map(|v| v.reconstruct()).collect::<Vec<_>>();
        });
    }
}
