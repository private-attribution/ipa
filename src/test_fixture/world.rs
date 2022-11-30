use crate::rand::thread_rng;
use async_trait::async_trait;
use futures::{future::join_all, Future};
use rand::{distributions::Standard, prelude::Distribution};

use crate::sync::atomic::{AtomicUsize, Ordering};
use crate::{
    ff::Field,
    helpers::{
        messaging::{Gateway, GatewayConfig},
        Role, SendBufferConfig,
    },
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        malicious::MaliciousValidator,
        prss::Endpoint as PrssEndpoint,
        QueryId,
    },
    secret_sharing::DowngradeMalicious,
    test_fixture::{logging, make_participants, network::InMemoryNetwork, sharing::IntoShares},
};
use std::{fmt::Debug, iter::zip, sync::Arc};

use super::{
    sharing::{IntoMalicious, ValidateMalicious},
    Reconstruct,
};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
pub struct TestWorld {
    pub query_id: QueryId,
    pub gateways: [Gateway; 3],
    pub participants: [PrssEndpoint; 3],
    pub(super) executions: AtomicUsize,
    _network: Arc<InMemoryNetwork>,
}

#[derive(Copy, Clone)]
pub struct TestWorldConfig {
    pub gateway_config: GatewayConfig,
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            gateway_config: GatewayConfig {
                send_buffer_config: SendBufferConfig {
                    /// This value set to 1 effectively means no buffering. This is the desired mode
                    /// for unit tests to drive them to completion as fast as possible.
                    items_in_batch: 1,

                    /// How many messages can be sent in parallel. This value is picked arbitrarily as
                    /// most unit tests don't send more than this value, so the setup does not have to
                    /// be annoying. `items_in_batch` * `batch_count` defines the total capacity for
                    /// send buffer. Increasing this value does not really impact the latency for tests
                    /// because they flush the data to network once they've accumulated at least
                    /// `items_in_batch` elements. Ofc setting it to some absurdly large value is going
                    /// to be problematic from memory perspective.
                    batch_count: 40,
                },
            },
        }
    }
}

impl TestWorld {
    /// Creates a new `TestWorld` instance using the provided `config`.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn new_with(query_id: QueryId, config: TestWorldConfig) -> TestWorld {
        logging::setup();

        let participants = make_participants();
        let network = InMemoryNetwork::new();
        let gateways = network
            .endpoints
            .iter()
            .map(|endpoint| Gateway::new(endpoint.role, endpoint, config.gateway_config))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        TestWorld {
            query_id,
            gateways,
            participants,
            executions: AtomicUsize::new(0),
            _network: network,
        }
    }

    /// Creates a new `TestWorld` instance.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn new(query_id: QueryId) -> TestWorld {
        let config = TestWorldConfig::default();
        Self::new_with(query_id, config)
    }

    /// Creates protocol contexts for 3 helpers
    ///
    /// # Panics
    /// Panics if world has more or less than 3 gateways/participants
    #[must_use]
    pub fn contexts<F: Field>(&self) -> [SemiHonestContext<'_, F>; 3] {
        let execution = self.executions.fetch_add(1, Ordering::Release);
        let run = format!("run-{execution}");
        zip(Role::all(), zip(&self.participants, &self.gateways))
            .map(|(role, (participant, gateway))| {
                SemiHonestContext::new(*role, participant, gateway).narrow(&run)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

#[async_trait]
pub trait Runner<I, A, F> {
    async fn semi_honest<'a, O, H, R>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        F: Field,
        O: Send + Debug,
        H: FnMut(SemiHonestContext<'a, F>, A) -> R + Send,
        R: Future<Output = O> + Send,
        Standard: Distribution<F>;

    async fn malicious<'a, O, M, H, R, P>(&'a self, input: I, helper_fn: H) -> [O; 3]
    where
        A: IntoMalicious<F, M>,
        F: Field,
        O: Send + Debug,
        M: Send,
        H: FnMut(MaliciousContext<'a, F>, M) -> R + Send,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>;
}

#[async_trait]
impl<I, A, F> Runner<I, A, F> for TestWorld
where
    I: 'static + IntoShares<A> + Send,
    A: Send,
    F: Field,
{
    async fn semi_honest<'a, O, H, R>(&'a self, input: I, mut helper_fn: H) -> [O; 3]
    where
        F: Field,
        O: Send + Debug,
        H: FnMut(SemiHonestContext<'a, F>, A) -> R + Send,
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

    async fn malicious<'a, O, M, H, R, P>(&'a self, input: I, mut helper_fn: H) -> [O; 3]
    where
        A: IntoMalicious<F, M>,
        F: Field,
        O: Send + Debug,
        M: Send,
        H: FnMut(MaliciousContext<'a, F>, M) -> R + Send,
        R: Future<Output = P> + Send,
        P: DowngradeMalicious<Target = O> + Send + Debug,
        [P; 3]: ValidateMalicious<F>,
        Standard: Distribution<F>,
    {
        // The following is what this *should* look like,
        // but so far the spelling necessary to convince the borrow checker
        // to accept this has not been found.
        //
        // Current theory is that this might allow `helper_fn` to be run
        // on multiple different threads concurrently, which would be bad.
        // The long form below ensures that it is only run on one thread,
        // even if it might move (with `Send`) a few times before it runs.

        #[cfg(exemplary_code)]
        {
            self.semi_honest(input, |ctx, share| async {
                let v = MaliciousValidator::new(ctx);
                let m_share = share.upgrade(v.context()).await;
                let res = helper_fn(v.context(), m_share).await;
                v.validate(res).await.unwrap()
            })
            .await
        }

        // Convert the shares from I into [A; 3].
        let contexts = self.contexts();
        let input_shares = {
            let mut rng = thread_rng();
            input.share_with(&mut rng)
        };

        // Generate and return for each helper:
        // a) malicious validator; b) upgraded the shares (from A to M)
        let upgraded = join_all(zip(contexts, input_shares).map(|(ctx, share)| async {
            let v = MaliciousValidator::new(ctx);
            let m_share = share.upgrade(v.context()).await;
            (v, m_share)
        }))
        .await;

        // Separate the validators and the now-malicious shares.
        let (v, m_shares): (Vec<_>, Vec<_>) = upgraded.into_iter().unzip();
        let r = (v[0].r_share(), v[1].r_share(), v[2].r_share()).reconstruct();

        // Reference the validator to produce malicious contexts,
        // and process the inputs M and produce Future R which can be awaited to P.
        // Note: all this messing around is to isolate this call so that it
        // doesn't need to use an `async` block.
        let m_results =
            join_all(zip(v.iter(), m_shares).map(|(v, m_share)| helper_fn(v.context(), m_share)))
                .await;
        let m_results = <[_; 3]>::try_from(m_results).unwrap();
        m_results.validate(r);

        // Perform validation and convert the results we just got: P to O
        let output = join_all(
            zip(v, m_results).map(|(v, m_result)| async { v.validate(m_result).await.unwrap() }),
        )
        .await;
        <[_; 3]>::try_from(output).unwrap()
    }
}
