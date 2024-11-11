// We have quite a bit of code that is only used when descriptive-gate is enabled.
#![allow(dead_code)]
use std::{
    array::from_fn,
    borrow::Borrow,
    fmt::Debug,
    io::stdout,
    iter::{self, zip},
    marker::PhantomData,
    sync::Mutex,
};

use async_trait::async_trait;
use futures::{future::join_all, stream::FuturesOrdered, Future, StreamExt};
use rand::{
    distributions::{Distribution, Standard},
    rngs::StdRng,
    CryptoRng, Rng, RngCore, SeedableRng,
};
use tracing::{Instrument, Level, Span};

use crate::{
    helpers::{
        in_memory_config::{passthrough, DynStreamInterceptor},
        Gateway, GatewayConfig, HelperIdentity, InMemoryMpcNetwork, InMemoryShardNetwork,
        InMemoryTransport, Role, RoleAssignment, TotalRecords, Transport,
    },
    protocol::{
        context::{
            dzkp_validator::DZKPValidator, upgrade::Upgradable, Context,
            DZKPUpgradedMaliciousContext, DZKPUpgradedSemiHonestContext, MaliciousContext,
            SemiHonestContext, ShardedMaliciousContext, ShardedSemiHonestContext,
            UpgradableContext, UpgradedContext, UpgradedMaliciousContext, Validator,
            TEST_DZKP_STEPS,
        },
        prss::Endpoint as PrssEndpoint,
        Gate, QueryId, RecordId,
    },
    rand::thread_rng,
    secret_sharing::{
        replicated::malicious::{
            DowngradeMalicious, ExtendableField, ThisCodeIsAuthorizedToDowngradeFromMalicious,
        },
        IntoShares,
    },
    sharding::{NotSharded, ShardBinding, ShardIndex, Sharded},
    telemetry::{stats::Metrics, StepStatsCsvExporter},
    test_fixture::{
        logging, make_participants,
        metrics::MetricsHandle,
        shard_configurator::{Configurator, ShardConfigurator},
        sharing::ValidateMalicious,
        test_gate::{gate_vendor, TestGateVendor},
        Reconstruct,
    },
    utils::array::zip3_ref,
};

pub trait ShardingScheme: Sized {
    type Container<A>;
    type Configurator: ShardConfigurator<Self::ShardBinding>;
    /// This type reflects how this scheme binds to [`ShardBinding`] interface used in [`Context`].
    /// Single shard systems do not use sharding capabilities, so the point of shard index is moot
    /// Multi-shard system must inform MPC circuits about shard they operate on and total number
    /// of shards within the system.
    ///
    /// See [`NotSharded`], [`WithShards`] and [`ShardBinding`]
    type ShardBinding: ShardBinding;
    /// Number of shards used inside the test world.
    const SHARDS: usize;

    /// This sets up a new shard, creating its configurator.
    fn new_shard(shard_index: ShardIndex, cs_prss_seed: u64) -> Self::Configurator;
}

/// Helper trait to parametrize [`Runner`] trait based on the sharding scheme chosen. The whole
/// purpose of it is to be able to say for sharded runs, the input must be in a form of a [`Vec`]
pub trait RunnerInput<S: ShardingScheme, A: Send>: Send {
    fn share_with<R: Rng>(self, rng: &mut R) -> [S::Container<A>; 3];
}

/// Trait that defines how helper inputs are distributed across shards. The simplest implementation
/// is [`RoundRobin`] and it is used by default. To test protocol correctness, it is a good idea
/// to use other strategies, namely [`Random`]
pub trait Distribute {
    fn distribute<const SHARDS: usize, A>(input: Vec<A>) -> [Vec<A>; SHARDS];
}

/// This indicates how many shards need to be created in test environment.
pub struct WithShards<const SHARDS: usize, D: Distribute = RoundRobin> {
    _phantom: PhantomData<fn() -> D>,
}

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
    shards: Box<[ShardWorld<S>]>,
    metrics_handle: MetricsHandle,
    // Using a mutex here is not as unfortunate as it might initially appear, because we
    // only use this RNG as a source of seeds for other RNGs. See `fn rng`.
    rng: Mutex<StdRng>,
    gate_vendor: Box<dyn TestGateVendor>,
    _shard_network: InMemoryShardNetwork,
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
    /// The gate to start on. If left empty, a unique gate per test run will be created, allowing
    /// the use of [`TestWorld`] for multiple runs.
    /// For anything other than compact gate, you'll want to leave it empty. Only if you care about
    /// performance and want to use compact gates, you set this to the gate narrowed to root step
    /// of the protocol being tested.
    pub initial_gate: Option<Gate>,

    /// An optional interceptor to be put inside the in-memory stream
    /// module. This allows inspecting and modifying stream content
    /// for each communication round between any pair of helpers.
    /// The application include:
    /// * Malicious behavior. This can help simulating a malicious
    ///     actor being present in the system by running one or several
    ///     additive attacks.
    /// * Data corruption. Tests can simulate bit flips that occur
    ///     at the network layer and check whether IPA can recover from
    ///     these (checksums, etc).
    ///
    /// The interface is pretty low level because of the layer
    /// where it operates. [`StreamInterceptor`] interface provides
    /// access to the circuit gate and raw bytes being
    /// sent between helpers and/or shards. [`MaliciousHelper`]
    /// is one example of helper that could be built on top
    /// of this generic interface. It is recommended to build
    /// a custom interceptor for repeated use-cases that is less
    /// generic than [`StreamInterceptor`].
    ///
    /// If interception is not required, the [`passthrough`] interceptor
    /// may be used.
    ///
    /// [`StreamInterceptor`]: crate::helpers::in_memory_config::StreamInterceptor
    /// [`MaliciousHelper`]: crate::helpers::in_memory_config::MaliciousHelper
    /// [`passthrough`]: crate::helpers::in_memory_config::passthrough
    pub stream_interceptor: DynStreamInterceptor,
}

impl ShardingScheme for NotSharded {
    /// For single-sharded worlds, there is no need to have the ability to distribute data across
    /// shards. Any MPC circuit can take even a single share as input and produce meaningful outcome.
    type Container<A> = A;
    type Configurator = Configurator<Self>;
    type ShardBinding = Self;
    const SHARDS: usize = 1;

    fn new_shard(_shard_index: ShardIndex, _cs_prss_seed: u64) -> Self::Configurator {
        Self::Configurator::default()
    }
}

impl<const N: usize, D: Distribute> ShardingScheme for WithShards<N, D> {
    /// The easiest way to distribute data across shards is to take a collection with a known size
    /// as input.
    type Container<A> = Vec<A>;
    type Configurator = Configurator<Self>;
    type ShardBinding = Sharded;
    const SHARDS: usize = N;

    fn new_shard(shard_index: ShardIndex, cs_prss_seed: u64) -> Self::Configurator {
        Self::Configurator::new(shard_index, cs_prss_seed)
    }
}

impl Default for TestWorld<NotSharded> {
    fn default() -> Self {
        Self::new_with(TestWorldConfig::default())
    }
}

impl<const SHARDS: usize, D: Distribute> TestWorld<WithShards<SHARDS, D>> {
    /// For backward compatibility, this method must have a different name than [`non_sharded`] method.
    ///
    /// [`non_sharded`]: TestWorld::<NotSharded>::new_with
    #[must_use]
    pub fn with_shards<B: Borrow<TestWorldConfig>>(config: B) -> Self {
        Self::with_config(config.borrow())
    }

    fn shards(&self) -> [&ShardWorld<WithShards<SHARDS, D>>; SHARDS] {
        self.shards
            .iter()
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }

    /// Creates protocol contexts for 3 helpers across all shards
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts(&self) -> [Vec<ShardedSemiHonestContext<'_>>; 3] {
        let gate = &self.next_gate();
        self.shards().iter().map(|shard| shard.contexts(gate)).fold(
            [Vec::new(), Vec::new(), Vec::new()],
            |mut acc, contexts| {
                // Distribute contexts into the respective vectors.
                for (vec, context) in acc.iter_mut().zip(contexts.iter()) {
                    vec.push(context.clone());
                }
                acc
            },
        )
    }
    /// Creates malicious protocol contexts for 3 helpers across all shards
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn malicious_contexts(&self) -> [Vec<ShardedMaliciousContext<'_>>; 3] {
        self.shards()
            .iter()
            .map(|shard| shard.malicious_contexts(&self.next_gate()))
            .fold([Vec::new(), Vec::new(), Vec::new()], |mut acc, contexts| {
                // Distribute contexts into the respective vectors.
                for (vec, context) in acc.iter_mut().zip(contexts.iter()) {
                    vec.push(context.clone());
                }
                acc
            })
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

    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self::new_with(TestWorldConfig::default().with_seed(seed))
    }

    /// Creates protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts(&self) -> [SemiHonestContext<'_>; 3] {
        self.shards[0].contexts(&self.next_gate())
    }

    /// Creates malicious protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn malicious_contexts(&self) -> [MaliciousContext<'_>; 3] {
        self.shards[0].malicious_contexts(&self.next_gate())
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
        if tracing::span_enabled!(Level::DEBUG) {
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
        println!("TestWorld random seed {seed}", seed = config.seed);
        let mut rng = StdRng::seed_from_u64(config.seed);

        // Create global PRSS seed. Each participant tracks the usage of it,
        // so we need to vend unique instance per shard
        let global_prss_rng_seed = rng.next_u64();

        let shard_count = ShardIndex::try_from(S::SHARDS).unwrap();
        let shard_network =
            InMemoryShardNetwork::with_stream_interceptor(shard_count, &config.stream_interceptor);

        let shards = shard_count
            .iter()
            .map(|shard_id| {
                ShardWorld::new(
                    S::new_shard(shard_id, global_prss_rng_seed),
                    config,
                    &mut rng,
                    shard_network.shard_transports(shard_id),
                )
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            shards,
            metrics_handle: MetricsHandle::new(config.metrics_level),
            rng: Mutex::new(rng),
            gate_vendor: gate_vendor(config.initial_gate.clone()),
            _shard_network: shard_network,
        }
    }

    #[must_use]
    pub(crate) fn gate(&self) -> Gate {
        self.gate_vendor.current()
    }

    #[must_use]
    fn next_gate(&self) -> Gate {
        self.gate_vendor.next()
    }

    /// Return a new `Rng` seeded from the primary `TestWorld` RNG.
    ///
    /// ## Panics
    /// If the mutex is poisoned.
    #[must_use]
    pub fn rng(&self) -> impl Rng + CryptoRng {
        // We need to use the `TestWorld` RNG within the `Runner` helpers, which
        // unfortunately take `&self`.
        // Note that this RNG is not cryptographically secure. For one, it's seeded
        // with a known config value. It's also seeded with non-secure entropy.
        // However, in order to test cryptographic functions that require an
        // RNG with the `CryptoRng`, we add it here.
        StdRng::from_seed(self.rng.lock().unwrap().gen())
    }
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            // Only keep a small amount of active work on hand.
            gateway_config: GatewayConfig {
                active: 16.try_into().unwrap(),
                ..Default::default()
            },
            // Disable metrics by default because `logging` only enables `Level::INFO` spans.
            // Can be overridden by setting `RUST_LOG` environment variable to match this level.
            metrics_level: Level::DEBUG,
            role_assignment: None,
            seed: thread_rng().next_u64(),
            initial_gate: None,
            stream_interceptor: passthrough(),
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
    fn share_with<R: Rng>(self, rng: &mut R) -> [A; 3] {
        I::share_with(self, rng)
    }
}

impl<const SHARDS: usize, I, A, D> RunnerInput<WithShards<SHARDS, D>, A> for I
where
    I: IntoShares<Vec<A>> + Send,
    A: Send,
    D: Distribute,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<A>; 3] {
        I::share_with(self, rng)
    }
}

#[async_trait]
pub trait Runner<S: ShardingScheme> {
    /// This could be also derived from [`S`], but maybe that's too much for that trait.
    type SemiHonestContext<'ctx>: Context;
    /// The type of context used to run protocols that are secure against
    /// active adversaries. It varies depending on whether sharding is used or not.
    type MaliciousContext<'ctx>: Context;

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
    async fn malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> S::Container<[O; 3]>
    where
        I: RunnerInput<S, A>,
        A: Send,
        O: Send + Debug,
        H: Fn(Self::MaliciousContext<'a>, S::Container<A>) -> R + Send + Sync,
        R: Future<Output = O> + Send;

    /// Run with a context that has already been upgraded to malicious.
    async fn upgraded_malicious<'a, F, I, A, M, O, H, R, P>(
        &'a self,
        input: I,
        helper_fn: H,
    ) -> [Vec<O>; 3]
    where
        F: ExtendableField,
        I: IntoShares<Vec<A>> + Send + 'static,
        A: Send + 'static + Upgradable<UpgradedMaliciousContext<'a, F>, Output = M>,
        O: Send + Debug,
        M: Send + 'static,
        H: Fn(UpgradedMaliciousContext<'a, F>, RecordId, M) -> R + Send + Sync,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Clone + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>;

    /// Run with a context that has already been upgraded to DZKP semi-honest.
    async fn dzkp_semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        O: Send + Debug,
        H: Fn(DZKPUpgradedSemiHonestContext<'a, NotSharded>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send;

    /// Run with a context that has already been upgraded to DZKP malicious.
    async fn dzkp_malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        O: Send + Debug,
        H: Fn(DZKPUpgradedMaliciousContext<'a, NotSharded>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send;
}

/// Separate a length-3 array of tuples (T, U, V) into a tuple of length-3
/// arrays of T's, U's, and V's.
fn split_array_of_tuples<T, U, V>(v: [(T, U, V); 3]) -> ([T; 3], [U; 3], [V; 3]) {
    let [v0, v1, v2] = v;
    ([v0.0, v1.0, v2.0], [v0.1, v1.1, v2.1], [v0.2, v1.2, v2.2])
}

#[async_trait]
impl<const SHARDS: usize, D: Distribute> Runner<WithShards<SHARDS, D>>
    for TestWorld<WithShards<SHARDS, D>>
{
    type SemiHonestContext<'ctx> = ShardedSemiHonestContext<'ctx>;
    type MaliciousContext<'ctx> = ShardedMaliciousContext<'ctx>;
    async fn semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> Vec<[O; 3]>
    where
        I: RunnerInput<WithShards<SHARDS, D>, A>,
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
        let mut rng = self.rng();
        let [h1, h2, h3]: [[Vec<A>; SHARDS]; 3] = input.share_with(&mut rng).map(D::distribute);
        let gate = self.next_gate();

        // No clippy, you're wrong, it is not redundant, it allows shard_fn to be `Copy`
        #[allow(clippy::redundant_closure)]
        let shard_fn = |ctx, input| helper_fn(ctx, input);
        zip(shards.into_iter(), zip(zip(h1, h2), h3))
            .map(|(shard, ((h1, h2), h3))| {
                ShardWorld::<WithShards<SHARDS, D>>::run_either(
                    shard.contexts(&gate),
                    self.metrics_handle.span(),
                    [h1, h2, h3],
                    shard_fn,
                )
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
    }

    async fn malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> Vec<[O; 3]>
    where
        I: RunnerInput<WithShards<SHARDS, D>, A>,
        A: Send,
        O: Send + Debug,
        H: Fn(
                Self::MaliciousContext<'a>,
                <WithShards<SHARDS> as ShardingScheme>::Container<A>,
            ) -> R
            + Send
            + Sync,
        R: Future<Output = O> + Send,
    {
        let shards = self.shards();
        let mut rng = self.rng();
        let [h1, h2, h3]: [[Vec<A>; SHARDS]; 3] = input.share_with(&mut rng).map(D::distribute);
        let gate = self.next_gate();

        // No clippy, you're wrong, it is not redundant, it allows shard_fn to be `Copy`
        #[allow(clippy::redundant_closure)]
        let shard_fn = |ctx, input| helper_fn(ctx, input);
        zip(shards.into_iter(), zip(zip(h1, h2), h3))
            .map(|(shard, ((h1, h2), h3))| {
                ShardWorld::<WithShards<SHARDS, D>>::run_either(
                    shard.malicious_contexts(&gate),
                    self.metrics_handle.span(),
                    [h1, h2, h3],
                    shard_fn,
                )
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
    }

    async fn upgraded_malicious<'a, F, I, A, M, O, H, R, P>(
        &'a self,
        _input: I,
        _helper_fn: H,
    ) -> [Vec<O>; 3]
    where
        F: ExtendableField,
        I: IntoShares<Vec<A>> + Send + 'static,
        A: Send + 'static + Upgradable<UpgradedMaliciousContext<'a, F>, Output = M>,
        O: Send + Debug,
        M: Send + 'static,
        H: Fn(UpgradedMaliciousContext<'a, F>, RecordId, M) -> R + Send + Sync,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Clone + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>,
    {
        unimplemented!()
    }

    /// Run with a context that has already been upgraded to DZKP semi-honest.
    async fn dzkp_semi_honest<'a, I, A, O, H, R>(&'a self, _input: I, _helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        O: Send + Debug,
        H: Fn(DZKPUpgradedSemiHonestContext<'a, NotSharded>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        unimplemented!()
    }

    /// Run with a context that has already been upgraded to DZKP malicious.
    async fn dzkp_malicious<'a, I, A, O, H, R>(&'a self, _input: I, _helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        O: Send + Debug,
        H: Fn(DZKPUpgradedMaliciousContext<'a, NotSharded>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        unimplemented!()
    }
}

#[async_trait]
impl Runner<NotSharded> for TestWorld<NotSharded> {
    type SemiHonestContext<'ctx> = SemiHonestContext<'ctx>;
    type MaliciousContext<'ctx> = MaliciousContext<'ctx>;

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
            input.share_with(&mut self.rng()),
            helper_fn,
        )
        .await
    }

    async fn malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: RunnerInput<NotSharded, A>,
        A: Send,
        O: Send + Debug,
        H: Fn(Self::MaliciousContext<'a>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        ShardWorld::<NotSharded>::run_either(
            self.malicious_contexts(),
            self.metrics_handle.span(),
            input.share_with(&mut self.rng()),
            helper_fn,
        )
        .await
    }

    async fn upgraded_malicious<'a, F, I, A, M, O, H, R, P>(
        &'a self,
        input: I,
        helper_fn: H,
    ) -> [Vec<O>; 3]
    where
        F: ExtendableField,
        I: IntoShares<Vec<A>> + Send + 'static,
        A: Send + 'static + Upgradable<UpgradedMaliciousContext<'a, F>, Output = M>,
        O: Send + Debug,
        M: Send + 'static,
        H: Fn(UpgradedMaliciousContext<'a, F>, RecordId, M) -> R + Send + Sync,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Clone + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>,
    {
        // Closure is Copy, so we don't need to fight rustc convincing it
        // that it is ok to use `helper_fn` in `malicious` closure.
        #[allow(clippy::redundant_closure)]
        let helper_fn = |ctx, record_id, m_share| helper_fn(ctx, record_id, m_share);

        let (m_results, r_shares, output) = split_array_of_tuples(
            self.malicious(input, |ctx, shares| async move {
                let ctx = ctx.set_total_records(
                    TotalRecords::specified(shares.len()).expect("Non-empty input"),
                );
                let v = ctx.validator::<F>();
                let m_ctx = v.context();
                let r_share = m_ctx.clone().r(RecordId::FIRST).clone();

                // Clippy doesn't like join_all, as it can spawn too many futures.
                // This only spawns 3, so it's OK.
                #[allow(clippy::disallowed_methods)]
                let m_shares: Vec<_> =
                    join_all(zip(shares, iter::repeat(m_ctx.clone())).enumerate().map(
                        |(i, (share, m_ctx))| async move {
                            let record_id = RecordId::from(i);
                            let m_share = share.upgrade(m_ctx.clone(), record_id).await.unwrap();
                            let m_result = helper_fn(m_ctx.clone(), record_id, m_share).await;
                            m_ctx.validate_record(record_id).await.unwrap();

                            (
                                m_result.clone(),
                                m_result.downgrade().await.access_without_downgrade(),
                            )
                        },
                    ))
                    .await;

                let (m_results, outputs): (Vec<_>, Vec<_>) = m_shares.into_iter().unzip();

                (m_results, r_share, outputs)
            })
            .await,
        );

        // Sanity check that rx = r * x at the output (it should not be possible
        // for this to fail if the distributed validation protocol passed).
        let r = r_shares.reconstruct();
        let [h1_r, h2_r, h3_r] = m_results;
        for (h1, (h2, h3)) in zip(h1_r, zip(h2_r, h3_r)) {
            [h1, h2, h3].validate(r);
        }

        output
    }

    async fn dzkp_semi_honest<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send,
        O: Send + Debug,
        H: Fn(DZKPUpgradedSemiHonestContext<'a, NotSharded>, A) -> R + Send + Sync,
        R: Future<Output = O> + Send,
    {
        ShardWorld::<NotSharded>::run_either(
            self.contexts(),
            self.metrics_handle.span(),
            input.share(),
            |ctx, share| async {
                let v = ctx.dzkp_validator(TEST_DZKP_STEPS, 8);
                let m_ctx = v.context();
                let m_result = helper_fn(m_ctx, share).await;
                v.validate().await.unwrap();
                m_result
            },
        )
        .await
    }

    /// Run with a context that has already been upgraded to malicious.
    async fn dzkp_malicious<'a, I, A, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        I: IntoShares<A> + Send + 'static,
        A: Send + 'static,
        O: Send + Debug,
        H: (Fn(DZKPUpgradedMaliciousContext<'a, NotSharded>, A) -> R) + Send + Sync,
        R: Future<Output = O> + Send,
    {
        self.malicious(input, |ctx, share| async {
            let v = ctx.dzkp_validator(TEST_DZKP_STEPS, 8);
            let m_ctx = v.context();
            let m_result = helper_fn(m_ctx, share).await;
            v.validate().await.unwrap();
            m_result
        })
        .await
    }
}

struct ShardWorld<S: ShardingScheme> {
    shard_constructor: S::Configurator,
    gateways: [Gateway; 3],
    // Per-shard shared randomness. Two different shards on the same helper
    // will have unique shard participants and use them as PRSS for MPC protocols
    shard_participants: [PrssEndpoint; 3],
    // It will be used once Gateway knows how to route shard traffic
    _shard_connections: [InMemoryTransport<ShardIndex>; 3],
    _mpc_network: InMemoryMpcNetwork,
}

impl<S: ShardingScheme> ShardWorld<S> {
    pub fn new(
        shard_constructor: S::Configurator,
        config: &TestWorldConfig,
        rng: &mut StdRng,
        transports: [InMemoryTransport<ShardIndex>; 3],
    ) -> Self {
        let participants = make_participants(rng);

        let network = InMemoryMpcNetwork::with_stream_interceptor(
            InMemoryMpcNetwork::noop_handlers(),
            &config.stream_interceptor,
            shard_constructor.shard_id(),
        );

        let mut gateways = zip3_ref(&network.transports(), &transports).map(|(mpc, shard)| {
            Gateway::new(
                QueryId,
                config.gateway_config,
                config.role_assignment().clone(),
                Transport::clone_ref(mpc),
                Transport::clone_ref(shard),
            )
        });

        // The name for `g` is too complicated and depends on features enabled
        #[allow(clippy::redundant_closure_for_method_calls)]
        gateways.sort_by_key(|g| g.role());

        ShardWorld {
            shard_constructor,
            gateways,
            shard_participants: participants,
            _shard_connections: transports,
            _mpc_network: network,
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
    pub fn contexts(&self, gate: &Gate) -> [SemiHonestContext<'_, S::ShardBinding>; 3] {
        zip3_ref(&self.shard_participants, &self.gateways).map(|(participant, gateway)| {
            SemiHonestContext::new_with_gate(
                participant,
                gateway,
                self.shard_constructor.bind(gateway.role()),
                gate.clone(),
            )
        })
    }

    /// Creates malicious protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn malicious_contexts(&self, gate: &Gate) -> [MaliciousContext<'_, S::ShardBinding>; 3] {
        zip3_ref(&self.shard_participants, &self.gateways).map(|(participant, gateway)| {
            MaliciousContext::new_with_gate(
                participant,
                gateway,
                gate.clone(),
                self.shard_constructor.bind(gateway.role()),
            )
        })
    }
}

/// Strategy to distribute shard inputs as evenly as possible across shards using Round-robin
/// technique.
pub struct RoundRobin;

impl Distribute for RoundRobin {
    fn distribute<const SHARDS: usize, A>(input: Vec<A>) -> [Vec<A>; SHARDS] {
        let mut r: [_; SHARDS] = from_fn(|_| Vec::new());
        for (i, share) in input.into_iter().enumerate() {
            r[i % SHARDS].push(share);
        }

        r
    }
}

/// Randomly distributes inputs across shards using the seed provided for randomness.
pub struct Random<const SEED: u64 = 0>;

impl<const SEED: u64> Distribute for Random<SEED> {
    fn distribute<const SHARDS: usize, A>(input: Vec<A>) -> [Vec<A>; SHARDS] {
        let mut r: [_; SHARDS] = from_fn(|_| Vec::new());
        let mut rng = StdRng::seed_from_u64(SEED);
        for share in input {
            let dest = rng.gen_range(0..SHARDS);
            r[dest].push(share);
        }

        r
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        iter,
        sync::{Arc, Mutex},
    };

    use futures_util::future::try_join4;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA3, BA64, BA8},
            ArrayAccess, Field, Fp31, U128Conversions,
        },
        helpers::{
            in_memory_config::{MaliciousHelper, MaliciousHelperContext},
            Direction, Role, TotalRecords,
        },
        protocol::{
            basics::SecureMul,
            boolean::step::EightBitStep,
            context::{
                dzkp_validator::DZKPValidator, upgrade::Upgradable, Context, DZKPContext,
                ShardedContext, UpgradableContext, UpgradedContext, Validator, TEST_DZKP_STEPS,
            },
            ipa_prf::boolean_ops::addition_sequential::integer_add,
            prss::SharedRandomness,
            RecordId,
        },
        rand::Rng,
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
            SharedValue,
        },
        sharding::{ShardConfiguration, ShardIndex},
        test_executor::{run, run_random},
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

    #[test]
    fn interceptor_can_corrupt_data() {
        const STEP: &str = "corruption";
        run(|| async move {
            fn corrupt_byte(data: &mut u8) {
                // flipping the bit may result in prime overflow,
                // so we just set the value to be 0 or 1 if it was 0
                if *data == 0 {
                    *data = 1;
                } else {
                    *data = 0;
                }
            }

            let mut config = TestWorldConfig::default();
            config.stream_interceptor = MaliciousHelper::new(
                Role::H1,
                config.role_assignment(),
                |ctx: &MaliciousHelperContext, data: &mut Vec<u8>| {
                    assert!(ctx.shard.is_none());
                    if ctx.gate.as_ref().contains(STEP) {
                        corrupt_byte(&mut data[0]);
                    }
                },
            );

            let world = TestWorld::new_with(config);

            let shares = world
                .semi_honest((), |ctx, ()| async move {
                    let ctx = ctx.narrow(STEP).set_total_records(1);
                    let (l, r): (Fp31, Fp31) = ctx.prss().generate(RecordId::FIRST);

                    let ((), (), r, l) = try_join4(
                        ctx.send_channel(ctx.role().peer(Direction::Right))
                            .send(RecordId::FIRST, r),
                        ctx.send_channel(ctx.role().peer(Direction::Left))
                            .send(RecordId::FIRST, l),
                        ctx.recv_channel::<Fp31>(ctx.role().peer(Direction::Right))
                            .receive(RecordId::FIRST),
                        ctx.recv_channel::<Fp31>(ctx.role().peer(Direction::Left))
                            .receive(RecordId::FIRST),
                    )
                    .await
                    .unwrap();

                    AdditiveShare::new(l, r)
                })
                .await;

            println!("{shares:?}");
            // shares received from H1 must be corrupted
            assert_ne!(shares[0].right(), shares[1].left());
            assert_ne!(shares[0].left(), shares[2].right());

            // and must be set to either 0 or 1
            assert!([Fp31::ZERO, Fp31::ONE].contains(&shares[1].left()));
            assert!([Fp31::ZERO, Fp31::ONE].contains(&shares[2].right()));

            // values shared between H2 and H3 must be consistent
            assert_eq!(shares[1].right(), shares[2].left());
        });
    }

    #[test]
    fn interceptor_can_corrupt_data_sharded() {
        const STEP: &str = "corruption";
        const TARGET_SHARD: ShardIndex = ShardIndex::FIRST;
        run(|| async move {
            fn corrupt_byte(data: &mut u8) {
                // flipping the bit may result in prime overflow,
                // so we just set the value to be 0 or 1 if it was 0
                if *data == 0 {
                    *data = 1;
                } else {
                    *data = 0;
                }
            }

            let mut config = TestWorldConfig::default();
            config.stream_interceptor = MaliciousHelper::new(
                Role::H1,
                config.role_assignment(),
                |ctx: &MaliciousHelperContext, data: &mut Vec<u8>| {
                    if ctx.shard.unwrap() == TARGET_SHARD && ctx.gate.as_ref().contains(STEP) {
                        corrupt_byte(&mut data[0]);
                    }
                },
            );

            let world: TestWorld<WithShards<2>> = TestWorld::with_shards(config);

            let shares = world
                .semi_honest(iter::empty::<Fp31>(), |ctx, _inputs| async move {
                    let ctx = ctx.narrow(STEP).set_total_records(1);
                    let (l, r): (Fp31, Fp31) = ctx.prss().generate(RecordId::FIRST);

                    let ((), (), r, l) = try_join4(
                        ctx.send_channel(ctx.role().peer(Direction::Right))
                            .send(RecordId::FIRST, r),
                        ctx.send_channel(ctx.role().peer(Direction::Left))
                            .send(RecordId::FIRST, l),
                        ctx.recv_channel::<Fp31>(ctx.role().peer(Direction::Right))
                            .receive(RecordId::FIRST),
                        ctx.recv_channel::<Fp31>(ctx.role().peer(Direction::Left))
                            .receive(RecordId::FIRST),
                    )
                    .await
                    .unwrap();

                    AdditiveShare::new(l, r)
                })
                .await;

            println!("{shares:?}");

            let shard0 = ShardIndex::FIRST;
            let shard1 = ShardIndex::from(1);

            // shares received from H1 on shard0 must be corrupted...
            assert_ne!(
                shares[shard0][Role::H1].right(),
                shares[shard0][Role::H2].left()
            );
            assert_ne!(
                shares[shard0][Role::H1].left(),
                shares[shard0][Role::H3].right()
            );

            // ... and must be set to either 0 or 1
            assert!([Fp31::ZERO, Fp31::ONE].contains(&shares[shard0][Role::H2].left()));
            assert!([Fp31::ZERO, Fp31::ONE].contains(&shares[shard0][Role::H3].right()));

            // shares received from H1 on shard1 must be consistent
            assert_eq!(
                shares[shard1][Role::H1].right(),
                shares[shard1][Role::H2].left()
            );
            assert_eq!(
                shares[shard1][Role::H1].left(),
                shares[shard1][Role::H3].right()
            );

            for shard in [shard0, shard1] {
                // values shared between H2 and H3 must be consistent
                assert_eq!(
                    shares[shard][Role::H2].right(),
                    shares[shard][Role::H3].left()
                );
            }
        });
    }

    #[test]
    fn zkp_malicious_sharded() {
        run(|| async {
            let world: TestWorld<WithShards<2>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![Boolean::truncate_from(0_u32), Boolean::truncate_from(1_u32)];
            let r = world
                .malicious(input.clone().into_iter(), |ctx, input| async move {
                    assert_eq!(1, input.iter().len());
                    let ctx = ctx.set_total_records(TotalRecords::ONE);
                    let validator = ctx.dzkp_validator(TEST_DZKP_STEPS, 1);
                    let ctx = validator.context();
                    let r = input[0]
                        .multiply(&input[0], ctx, RecordId::FIRST)
                        .await
                        .unwrap();
                    validator.validate().await.unwrap();

                    vec![r]
                })
                .await
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            assert_eq!(input, r);
        });
    }

    #[test]
    fn mac_malicious_sharded() {
        run(|| async {
            let world: TestWorld<WithShards<2>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![Fp31::truncate_from(0_u32), Fp31::truncate_from(1_u32)];
            let r = world
                .malicious(input.clone().into_iter(), |ctx, input| async move {
                    assert_eq!(1, input.iter().len());
                    let validator = ctx.set_total_records(1).validator();
                    let ctx = validator.context();
                    let (a_upgraded, b_upgraded) = (input[0].clone(), input[0].clone())
                        .upgrade(ctx.clone(), RecordId::FIRST)
                        .await
                        .unwrap();
                    let _ = a_upgraded
                        .multiply(&b_upgraded, ctx.narrow("multiply"), RecordId::FIRST)
                        .await
                        .unwrap();
                    ctx.validate_record(RecordId::FIRST).await.unwrap();

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
    fn mac_reproducible_from_seed() {
        run_random(|mut rng| async move {
            async fn test(seed: u64) -> Vec<u8> {
                let u_and_w = Arc::new(Mutex::new(vec![]));
                let u_and_w_ref = Arc::clone(&u_and_w);

                let mut config = TestWorldConfig::default();
                config.seed = seed;
                config.stream_interceptor = MaliciousHelper::new(
                    Role::H1,
                    config.role_assignment(),
                    move |ctx: &MaliciousHelperContext, data: &mut Vec<u8>| {
                        if ctx.gate.as_ref().contains("propagate_u_and_w") {
                            u_and_w_ref.lock().unwrap().extend(data.iter());
                        }
                    },
                );

                let world = TestWorld::with_config(&config);
                let mut rng = world.rng();
                let input: (Fp31, Fp31) = (rng.gen(), rng.gen());
                world
                    .malicious(input, |ctx, input| async move {
                        let validator = ctx.set_total_records(1).validator();
                        let ctx = validator.context();
                        let (a_upgraded, b_upgraded) = input
                            .clone()
                            .upgrade(ctx.clone(), RecordId::FIRST)
                            .await
                            .unwrap();
                        a_upgraded
                            .multiply(&b_upgraded, ctx.narrow("multiply"), RecordId::FIRST)
                            .await
                            .unwrap();
                        ctx.validate_record(RecordId::FIRST).await.unwrap();
                    })
                    .await;

                let result = u_and_w.lock().unwrap().clone();
                result
            }

            let seed = rng.gen();
            let first_result = test(seed).await;
            let second_result = test(seed).await;

            assert_eq!(first_result, second_result);
        });
    }

    #[test]
    fn zkp_reproducible_from_seed() {
        run_random(|mut rng| async move {
            async fn test(seed: u64) -> Vec<u8> {
                let proof_diff = Arc::new(Mutex::new(vec![]));
                let proof_diff_ref = Arc::clone(&proof_diff);

                let mut config = TestWorldConfig::default();
                config.seed = seed;
                config.stream_interceptor = MaliciousHelper::new(
                    Role::H1,
                    config.role_assignment(),
                    move |ctx: &MaliciousHelperContext, data: &mut Vec<u8>| {
                        if ctx.gate.as_ref().contains("verify_proof/diff") {
                            proof_diff_ref.lock().unwrap().extend(data.iter());
                        }
                    },
                );

                let world = TestWorld::with_config(&config);
                let mut rng = world.rng();
                let input: (BA8, BA8) = (rng.gen(), rng.gen());
                world
                    .malicious(input, |ctx, input| async move {
                        let validator = ctx.set_total_records(1).dzkp_validator(TEST_DZKP_STEPS, 8);
                        let ctx = validator.context();
                        integer_add::<_, EightBitStep, 1>(
                            ctx.clone(),
                            RecordId::FIRST,
                            &input.0.to_bits(),
                            &input.1.to_bits(),
                        )
                        .await
                        .unwrap();
                        ctx.validate_record(RecordId::FIRST).await.unwrap();
                    })
                    .await;

                let result = proof_diff.lock().unwrap().clone();
                result
            }

            let seed = rng.gen();
            let first_result = test(seed).await;
            let second_result = test(seed).await;

            assert_eq!(first_result, second_result);
        });
    }

    #[test]
    fn cross_shard_prss() {
        run(|| async {
            let world: TestWorld<WithShards<3>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![(), (), ()];
            let duplicates = Arc::new(Mutex::new(HashMap::new()));
            let _ = world
                .semi_honest(input.into_iter(), |ctx, _| {
                    let duplicates = Arc::clone(&duplicates);
                    async move {
                        let (l, r): (BA64, BA64) = ctx.narrow("step1").cross_shard_prss().generate(RecordId::FIRST);
                        {
                            println!("shard {} on {} generated ({l:?}, {r:?})", ctx.shard_id(), ctx.role());
                            let mut duplicates = duplicates.lock().unwrap();
                            let e = duplicates.entry(ctx.role()).or_insert_with(HashSet::new);
                            e.insert(l.as_u128());
                            e.insert(r.as_u128());
                            assert_eq!(2, e.len(), "Cross shard PRSS is broken: {e:?} is expected to contain exactly 2 entries");

                            let (l, r): (BA64, BA64) = ctx.narrow("step2").cross_shard_prss().generate(RecordId::FIRST);
                            assert!(!e.contains(&l.as_u128()) && !e.contains(&r.as_u128()), "Cross shard PRSS generated duplicates: {l:?} or {r:?} is in {e:?}");
                        }

                        let ctx = ctx.narrow("exchange").set_total_records(TotalRecords::ONE);

                        // ensure it is still PRSS, i.e. other MPC helpers have the same value
                        ctx.send_channel(ctx.role().peer(Direction::Left)).send(RecordId::FIRST, l).await.unwrap();
                        ctx.send_channel(ctx.role().peer(Direction::Right)).send(RecordId::FIRST, r).await.unwrap();

                        let from_left = ctx.recv_channel::<BA64>(ctx.role().peer(Direction::Left)).receive(RecordId::FIRST).await.unwrap();
                        let from_right = ctx.recv_channel::<BA64>(ctx.role().peer(Direction::Right)).receive(RecordId::FIRST).await.unwrap();

                        assert_eq!(l, from_left);
                        assert_eq!(r, from_right);
                    }
                })
                .await;
        });
    }
}
