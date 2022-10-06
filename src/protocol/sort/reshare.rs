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
use embed_doc_image::embed_doc_image;
use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've reshared their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PartValue<F> {
    part: F,
}
/// Reshare(i, [x])
// This implements reshare algorithm of "Efficient Secure Three-Party Sorting Protocol with an Honest Majority" at communication cost of 2R.
// Input: Pi-1 and Pi+1 know their secret shares
// Output: At the end of the protocol, all 3 helpers receive their shares of a new, random secret sharing of the secret value
#[derive(Debug)]
pub struct Reshare<F> {
    input: Replicated<F>,
}

impl<F: Field> Reshare<F> {
    #[allow(dead_code)]
    pub fn new(input: Replicated<F>) -> Self {
        Self { input }
    }

    /// Steps
    #[embed_doc_image("reshare", "images/sort/reshare.png")]
    /// 1. While calculating for helper, we call PRSS to get randoms for helper who needs to receive reshares (say `rand_left`, `rand_right`)
    ///    `to_helper.left` knows `rand_left` (named r1) and `to_helper.right` knows `rand_right` (named r0)
    /// 2. `to_helper.left` calculates part1 = (a1 + a2) - r2 = Same as (inputs.0 + inputs.1) - r1 from helper POV
    ///    `to_helper.right` calculates part2 = (a3 - r3) = Same as (inputs.0 - r0) from helper POV
    /// 3. `to_helper.left` and `to_helper.right` exchange their calculated shares
    /// 4. Everyone sets their shares  
    ///    `to_helper.left`  = (part1 + part2, `rand_left`)  = (part1 + part2, r1)
    ///    `to_helper`       = (`rand_left`, `rand_right`)     = (r0, r1)
    ///    `to_helper.right` = (`rand_right`, part1 + part2) = (r0, part1 + part2)
    #[allow(dead_code)]
    pub async fn execute<M: Mesh, G: Gateway<M, S>, S: Step + SpaceIndex>(
        self,
        ctx: &ProtocolContext<'_, G, S>,
        record_id: RecordId,
        step: S,
        to_helper: Identity,
    ) -> Result<Replicated<F>, BoxError> {
        let mut channel = ctx.gateway.get_channel(step);
        let prss = &ctx.participant[step];
        let (r0, r1) = prss.generate_fields(record_id.into());

        let inputs = self.input.as_tuple();
        // `to_helper.left` calculates part1 = (input.0 + input.1) - r1 and sends part1 to `to_helper.right`
        // This is same as (a1 + a2) - r2 in the diagram
        if channel.identity() == to_helper.peer(Direction::Left) {
            let part1 = inputs.0 + inputs.1 - r1;
            channel
                .send(
                    to_helper.peer(Direction::Right),
                    record_id,
                    PartValue { part: part1 },
                )
                .await?;

            // Sleep until `to_helper.right` sends us their part2 value
            let PartValue { part: part2 } = channel
                .receive(to_helper.peer(Direction::Right), record_id)
                .await?;

            Ok(Replicated::new(part1 + part2, r1))
        } else if channel.identity() == to_helper.peer(Direction::Right) {
            //  `to_helper.right` calculates part2 = (input.0 - r0) and sends it to `to_helper.left`
            // This is same as (a3 - r3) in the diagram
            let part2 = inputs.0 - r0;
            channel
                .send(
                    to_helper.peer(Direction::Left),
                    record_id,
                    PartValue { part: part2 },
                )
                .await?;

            // Sleep until `to_helper.left` sends us their part1 value
            let PartValue::<F> { part: part1 } = channel
                .receive(to_helper.peer(Direction::Left), record_id)
                .await?;

            Ok(Replicated::new(r0, part1 + part2))
        } else {
            Ok(Replicated::new(r0, r1))
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        helpers::Identity,
        protocol::{sort::reshare::Reshare, QueryId, RecordId},
        test_fixture::{
            make_contexts, make_world, share, validate_and_reconstruct, TestStep, TestWorld,
        },
    };

    #[tokio::test]
    pub async fn reshare() {
        let mut rand = StepRng::new(100, 1);
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let secret = rng.gen::<u128>();

            let input = Fp31::from(secret);
            let share = share(input, &mut rand);
            let record_id = RecordId::from(1);

            let world: TestWorld<TestStep> = make_world(QueryId);
            let context = make_contexts(&world);

            let step = TestStep::Reshare(1);

            let reshare0 = Reshare::new(share[0]);
            let reshare1 = Reshare::new(share[1]);
            let reshare2 = Reshare::new(share[2]);

            let h0_future = reshare0.execute(&context[0], record_id, step, Identity::H2);
            let h1_future = reshare1.execute(&context[1], record_id, step, Identity::H2);
            let h2_future = reshare2.execute(&context[2], record_id, step, Identity::H2);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();
            let output_share = validate_and_reconstruct(f);
            assert_eq!(output_share, input);
        }
    }
}
