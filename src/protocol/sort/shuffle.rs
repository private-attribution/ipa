use crate::helpers::prss::PrssSpace;
use permutation::Permutation;
use rand::rngs::mock::StepRng;
use rand::seq::SliceRandom;

use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;

use crate::{
    error::BoxError,
    field::Field,
    helpers::{
        mesh::{Gateway, Mesh},
        prss::SpaceIndex,
        Direction, Identity,
    },
    protocol::{context::ProtocolContext, RecordId, Step},
    secret_sharing::Replicated,
};

use super::{
    apply::apply_inv,
    reshare::Reshare,
    ShuffleStep::{self, Step1, Step2, Step3},
};

#[allow(dead_code)]
pub struct Shuffle<F, S> {
    input: Vec<Replicated<F>>,
    step_fn: fn(ShuffleStep) -> S,
}

/// This is SHUFFLE(Algorithm 1) described in <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol shuffles the given inputs across 3 helpers making them indistinguishable to the helpers
impl<F: Field, S: Step + SpaceIndex> Shuffle<F, S> {
    #[allow(dead_code)]
    pub fn new(input: Vec<Replicated<F>>, step_fn: fn(ShuffleStep) -> S) -> Self {
        Self { input, step_fn }
    }

    /// This implements Fisher Yates shuffle described here <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle>
    #[allow(clippy::cast_possible_truncation, dead_code)]
    fn generate_random_permutation(
        batchsize: usize,
        direction: Direction,
        index: u64,
        prss: &PrssSpace,
    ) -> Permutation {
        let mut permutation: Vec<usize> = (0..batchsize).collect();
        let rand = prss.generate_values(index.into());
        let mut rng = if direction == Direction::Left {
            StepRng::new(rand.0 as u64, 1)
        } else {
            StepRng::new(rand.1 as u64, 1)
        };
        permutation.shuffle(&mut rng);
        Permutation::from_vec(permutation)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn generate_random_permutations(
        &self,
        direction: Direction,
        prss: &PrssSpace,
        seed: u128,
    ) -> Permutation {
        let batchsize = self.input.len();
        let index = if direction == Direction::Left {
            prss.generate_values(seed).0
        } else {
            prss.generate_values(seed).1
        };

        Self::generate_random_permutation(batchsize, direction, index as u64, prss)
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn reshare_all_shares<M, G>(
        &self,
        ctx: &ProtocolContext<'_, G, S>,
        to_helper: Identity,
        step: S,
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        M: Mesh,
        G: Gateway<M, S>,
    {
        let reshares = self
            .input
            .iter()
            .enumerate()
            .map(|(index, input)| async move {
                Reshare::new(*input)
                    .execute(ctx, RecordId::from(index as u32), step, to_helper)
                    .await
            });
        try_join_all(reshares).await
    }

    /// `single_shuffle` is called for the helpers
    /// i) 2/3 helpers generate random sequence using shared prss random number
    /// ii) 2/3 helpers apply the permutation to their shares
    /// iii) reshare to `to_helper`
    async fn single_shuffle<M: Mesh, G: Gateway<M, S>>(
        &mut self,
        ctx: &ProtocolContext<'_, G, S>,
        seed: u128,
        to_helper: Identity,
        which_step: ShuffleStep,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let step = (self.step_fn)(which_step);
        let prss = &ctx.participant[step];
        let channel = ctx.gateway.get_channel(step);

        if to_helper != channel.identity() {
            let direction = if to_helper.peer(Direction::Left) == channel.identity() {
                Direction::Left
            } else {
                Direction::Right
            };
            let mut permute = self.generate_random_permutations(direction, prss, seed);
            apply_inv(&mut permute, &mut self.input);
        }
        self.reshare_all_shares(ctx, to_helper, step).await
    }

    /// Executes shuffling the inputs within mpc.
    /// Shuffle calls `single_shuffle` three times with 2/3 helpers shuffling the shares each time.
    /// Since each shuffle needs to be unique for the infrastructure to work, we have three steps to indicate that.
    /// Due to this, the Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step.
    #[embed_doc_image("reshare", "images/sort/shuffle.png")]
    #[allow(dead_code)]
    pub async fn execute<M: Mesh, G: Gateway<M, S>>(
        &mut self,
        ctx: &ProtocolContext<'_, G, S>,
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        F: Field,
    {
        // TODO : Need to find a way to have a better seed here. Can we use QueryID + SortStep combination to generate a seed?
        let seed = self.input.len().try_into().unwrap();
        self.input = self
            .single_shuffle(ctx, seed, Identity::H1, Step1)
            .await
            .unwrap();
        self.input = self
            .single_shuffle(ctx, seed, Identity::H2, Step2)
            .await
            .unwrap();
        self.input = self
            .single_shuffle(ctx, seed, Identity::H3, Step3)
            .await
            .unwrap();

        Ok(self.input.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::Direction;
    use rand::{rngs::mock::StepRng, Rng};
    use std::collections::HashSet;

    use super::Shuffle;
    use crate::{
        field::Fp31,
        protocol::sort::ShuffleStep::Step1,
        protocol::QueryId,
        test_fixture::{
            make_contexts, make_participants, make_world, share, validate_and_reconstruct,
            TestStep, TestWorld,
        },
    };
    use permutation::Permutation;
    use tokio::try_join;

    #[test]
    fn random_sequence_generated() {
        let mut rand = StepRng::new(1, 1);
        let batchsize = 10000;
        let (p1, p2, p3) = make_participants();
        let index = rand.gen::<u64>();
        let sequence1left = Shuffle::<Fp31, TestStep>::generate_random_permutation(
            batchsize,
            Direction::Left,
            index,
            &p1[TestStep::Shuffle(Step1)],
        );
        let sequence1right = Shuffle::<Fp31, TestStep>::generate_random_permutation(
            batchsize,
            Direction::Right,
            index,
            &p1[TestStep::Shuffle(Step1)],
        );

        let sequence2left = Shuffle::<Fp31, TestStep>::generate_random_permutation(
            batchsize,
            Direction::Left,
            index,
            &p2[TestStep::Shuffle(Step1)],
        );
        let sequence2right = Shuffle::<Fp31, TestStep>::generate_random_permutation(
            batchsize,
            Direction::Right,
            index,
            &p2[TestStep::Shuffle(Step1)],
        );

        let sequence3left = Shuffle::<Fp31, TestStep>::generate_random_permutation(
            batchsize,
            Direction::Left,
            index,
            &p3[TestStep::Shuffle(Step1)],
        );
        let sequence3right = Shuffle::<Fp31, TestStep>::generate_random_permutation(
            batchsize,
            Direction::Right,
            index,
            &p3[TestStep::Shuffle(Step1)],
        );

        assert_eq!(sequence1right, sequence2left);
        assert_eq!(sequence2right, sequence3left);
        assert_eq!(sequence3right, sequence1left);

        // Due to less randomness, the below three asserts can fail. However, the chance of failure is
        // 1/18Quintillian (a billion billion since u64 is used to generate randomness)! Hopefully we should not hit that
        assert_ne!(sequence1left, sequence1right);
        assert_ne!(sequence2left, sequence2right);
        assert_ne!(sequence3left, sequence3right);

        assert!(Permutation::valid(&sequence1right));
        assert!(Permutation::valid(&sequence2right));
        assert!(Permutation::valid(&sequence3right));
    }

    #[tokio::test]
    async fn shuffle() {
        let world: TestWorld<TestStep> = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rand = StepRng::new(100, 1);

        let input: HashSet<u8> = HashSet::from([4, 1, 9, 2, 3, 8, 6, 7, 5]);
        let input_len = input.len();

        let mut shares0 = Vec::with_capacity(input_len);
        let mut shares1 = Vec::with_capacity(input_len);
        let mut shares2 = Vec::with_capacity(input_len);

        input.clone().into_iter().for_each(|iter| {
            let share = share(Fp31::from(iter), &mut rand);
            shares0.push(share[0]);
            shares1.push(share[1]);
            shares2.push(share[2]);
        });

        let mut shuffle0 = Shuffle::new(shares0.clone(), TestStep::Shuffle);
        let mut shuffle1 = Shuffle::new(shares1.clone(), TestStep::Shuffle);
        let mut shuffle2 = Shuffle::new(shares2.clone(), TestStep::Shuffle);

        let h0_future = shuffle0.execute(&context[0]);
        let h1_future = shuffle1.execute(&context[1]);
        let h2_future = shuffle2.execute(&context[2]);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), input_len);
        assert_eq!(result.1.len(), input_len);
        assert_eq!(result.2.len(), input_len);

        let mut result0 = Vec::with_capacity(input_len);
        let mut result1 = Vec::with_capacity(input_len);
        let mut result2 = Vec::with_capacity(input_len);

        let mut output = HashSet::new();
        (0..result.0.len()).for_each(|i| {
            let val = validate_and_reconstruct((result.0[i], result.1[i], result.2[i]));

            result0.push(result.0[i]);
            result1.push(result.1[i]);
            result2.push(result.2[i]);
            output.insert(u8::from(val));
        });

        assert_ne!(result0, shares0);
        assert_ne!(result1, shares1);
        assert_ne!(result2, shares2);

        assert_eq!(output, input);
    }
}
