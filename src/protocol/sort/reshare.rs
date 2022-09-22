use axum::BoxError;

use crate::{
    field::Field,
    helpers::{
        mesh::{Gateway, Mesh},
        prss::{PrssSpace, SpaceIndex},
        Direction, Identity,
    },
    protocol::{DValue, RecordId, Step},
    secret_sharing::Replicated,
};

/// Reshare(i, [x])
// This implements reshare algorithm of "Efficient Secure Three-Party Sorting Protocol with an Honest Majority" at communication cost of 2R.
// Input: Pi-1 and Pi+1 knows their secret shares
// Output: At the end of the protocol, [all 3 helpers receive renewed shares of x with randomness added

#[derive(Debug)]
pub struct Reshare<'a, G, S> {
    gateway: &'a G,
    prss: &'a PrssSpace,
    record_id: RecordId,
    step: S,
}

impl<'a, G, S: Step + SpaceIndex> Reshare<'a, G, S> {
    #[allow(dead_code)]
    pub fn new(prss: &'a PrssSpace, gateway: &'a G, record_id: RecordId, step: S) -> Self {
        Self {
            gateway,
            prss,
            record_id,
            step,
        }
    }

    /// Steps
    /// 1. While calculating for helper, we call PRSS to get randoms for helper who needs to receive reshares (say r0, r1)
    ///    `to_helper.left` knows r0 (named r1) and `to_helper.right` knows r1 (named r0)
    /// 2. `to_helper.left` calculates part1 = (input.0 + input.1) - r1
    ///    `to_helper.right` calculates part2 = (input.0 - r0)
    /// 3. `to_helper.left` and `to_helper.right` exchange their calculated shares
    /// 4. Everyone sets their shares  
    ///    `to_helper.left` = (r0, part1 + part2))
    ///    `to_helper.right` = (part1 + part2, r1)
    ///    `to_helper`      = (r1, r0)

    #[allow(dead_code)]
    pub async fn execute<F, M>(
        self,
        input: Replicated<F>,
        to_helper: Identity,
    ) -> Result<Replicated<F>, BoxError>
    where
        F: Field + 'static,
        M: Mesh + 'a,
        G: Gateway<M, S>,
    {
        let mut channel = self.gateway.get_channel(self.step);

        let (r0, r1) = self.prss.generate_fields(self.record_id.into());

        let inputs = input.as_tuple();
        // `to_helper.left` calculates part1 = (input.0 + input.1) - r1 and sends part1 to `to_helper.right`
        if channel.identity() == to_helper.peer(Direction::Left) {
            let part1 = inputs.0 + inputs.1 - r1;
            channel
                .send(
                    to_helper.peer(Direction::Right),
                    self.record_id,
                    DValue { d: part1 },
                )
                .await?;

            // Sleep until `to_helper.left` sends us their part2 value

            let DValue { d: part2 } = channel
                .receive(channel.identity().peer(Direction::Left), self.record_id)
                .await?;

            Ok(Replicated::new(r1, part1 + part2))
        } else if channel.identity() == to_helper.peer(Direction::Right) {
            //  `to_helper.right` calculates part2 = (input.0 - r0) and sends it to `to_helper.left`
            let part2 = inputs.0 - r0;
            channel
                .send(
                    to_helper.peer(Direction::Left),
                    self.record_id,
                    DValue { d: part2 },
                )
                .await?;

            // Sleep until `to_helper.right` sends us their part1 value

            let DValue { d: part1 }: DValue<F> = channel
                .receive(channel.identity().peer(Direction::Right), self.record_id)
                .await?;

            Ok(Replicated::new(part1 + part2, r0))
        } else {
            Ok(Replicated::new(r1, r0))
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        helpers::Identity,
        protocol::{QueryId, RecordId},
        test_fixture::{
            make_contexts, make_world, share, validate_and_reconstruct, TestStep, TestWorld,
        },
    };

    #[tokio::test]
    pub async fn reshare() {
        let mut rand = StepRng::new(100, 1);

        let input = Fp31::from(23_u128);
        let share = share(input, &mut rand);
        let record_id = RecordId::from(1);

        let world: TestWorld<TestStep> = make_world(QueryId);
        let context = make_contexts(&world);

        let reshare1 = context[0]
            .reshare(record_id, TestStep::Reshare(1))
            .execute(share[0], Identity::H2);
        let reshare2 = context[1]
            .reshare(record_id, TestStep::Reshare(1))
            .execute(share[1], Identity::H2);
        let reshare3 = context[2]
            .reshare(record_id, TestStep::Reshare(1))
            .execute(share[2], Identity::H2);

        let f = try_join!(reshare1, reshare2, reshare3).unwrap();
        let output_share = validate_and_reconstruct(f);
        assert_eq!(output_share, input);
    }
}
