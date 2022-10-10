use super::{AttributionModel, RecordId};
use crate::{
    error::BoxError,
    field::Field,
    helpers::mesh::{Gateway, Mesh},
    protocol::context::ProtocolContext,
    secret_sharing::Replicated,
};
use futures::future::try_join_all;

/// Obilivious attribution protocol
///
/// Obliviously attribute trigger events to corresponding source events for different breakdowns in a MPC.
/// There are several common attribution models such as Last Touch, Even Credit and Exponential Decay.
/// https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution
#[allow(dead_code)]
pub struct Attribute<'a, G> {
    ctx: &'a ProtocolContext<'a, G, AttributionModel>,
    step: AttributionModel,
}

impl<'a, G> Attribute<'a, G> {
    const _IS_TRIGGER_BIT: usize = 2;
    const _HELPER_BIT: usize = 3;
    const _VALUE: usize = 5;

    #[allow(dead_code)]
    pub fn new(ctx: &'a ProtocolContext<'a, G, AttributionModel>, step: AttributionModel) -> Self {
        Self { ctx, step }
    }

    /// Executes the protocol and produces an attribution result for the model specified by `step` in `Attribute::new`.
    /// Attribution result will be used to calculate the aggregation in the next step.
    #[allow(dead_code)]
    pub async fn execute<M, F>(
        &self,
        input: &'a [Vec<Replicated<F>>],
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        M: Mesh,
        G: Gateway<M, AttributionModel>,
        F: Field,
    {
        match self.step {
            AttributionModel::LastTouch => self.last_touch_attribution(input).await,
        }
    }

    async fn last_touch_attribution<M, F>(
        &self,
        input: &'a [Vec<Replicated<F>>],
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        M: Mesh,
        G: Gateway<M, AttributionModel>,
        F: Field,
    {
        // TOOD: input length range check. Can we assume `assert!(num_rows < u32::MAX)`?
        let num_rows = input[0].len();

        // 1. Create Credit and Stop bit vectors
        let mut credits: Vec<Replicated<F>> = Vec::with_capacity(num_rows);
        input[Self::_VALUE].iter().for_each(|x| credits.push(*x));

        let one = self.ctx.gateway.get_channel(self.step).share_of_one::<F>();
        let mut stop_bits: Vec<Replicated<F>> = vec![one; num_rows];

        // 2. Accumulate
        //
        // Last touch accumulation algorithm:
        //     b = stop_bit * successor.helper_bit * successor.trigger_bit;
        //     credit = credit + b * successor.credit;
        //     stop_bit = b * successor.stop_bit;
        let mut step_size = 1;
        while step_size < num_rows {
            let end = num_rows - step_size;

            // first, calculate [successor.helper_bit * successor.trigger_bit]
            let mut b = self
                .multiply_all(
                    &input[Self::_HELPER_BIT][step_size..],
                    &input[Self::_IS_TRIGGER_BIT][step_size..],
                )
                .await?;

            // since `stop_bits` is initialized with `1`s, we only multiply [stop_bit] on the second and later iterations
            if step_size > 1 {
                b = self.multiply_all(&stop_bits[..end], &b).await?;
            }

            // [b * successor.credit]
            let b_cred = self.multiply_all(&b[..end], &credits[step_size..]).await?;

            // [credit] = [credit + b * successor.credit]
            b_cred
                .into_iter()
                .enumerate()
                .for_each(|(i, x)| credits[i] += x);

            // [stop_bit] = [b * successor.stop_bit]
            // for the same reason as calculating [b], we skip the multiplication on the first iteration
            let b_stop = if step_size > 1 {
                self.multiply_all(&b[..end], &stop_bits[step_size..])
                    .await?
            } else {
                b.clone()
            };

            b_stop
                .into_iter()
                .enumerate()
                .for_each(|(i, x)| stop_bits[i] = x);

            step_size *= 2;
        }

        Ok(credits)
    }

    async fn multiply_all<M, F>(
        &self,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        F: Field,
        M: Mesh,
        G: Gateway<M, AttributionModel>,
    {
        assert_eq!(a.len(), b.len());

        try_join_all((0..a.len()).map(|i| async move {
            let x = a[i];
            let y = b[i];

            // assume # of records < 2^32
            #[allow(clippy::cast_possible_truncation)]
            self.ctx
                .multiply(RecordId::from(i as u32), self.step)
                .await
                .execute(x, y)
                .await
        }))
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        field::{Field, Fp31},
        protocol::{attribute::Attribute, AttributionModel, QueryId},
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    #[tokio::test]
    pub async fn accumulate() {
        let world: TestWorld<AttributionModel> = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = StepRng::new(100, 1);

        let input: [[u128; 9]; 6] = [
            [1, 1, 1, 1, 1, 1, 1, 2, 3],
            [2, 5, 8, 9, 10, 13, 27, 11, 14],
            [0, 0, 1, 1, 1, 1, 1, 0, 1],
            [0, 1, 1, 1, 1, 1, 1, 0, 0],
            [3, 4, 0, 0, 0, 0, 0, 1, 0],
            [0, 0, 10, 2, 1, 5, 1, 0, 10],
        ];

        // Attribution Step (last touch):
        // Iter 0             [0,  0, 10, 2, 1, 5, 1, 0, 10]
        // Stop bits           -  --  --  -  -  -  -  -  --
        // Iter 1 (step = 1)  [0, 10, 12, 3, 6, 6, 1, 0, 10]
        // Stop bits              --  --  -  -  -
        // Iter 2 (step = 2)  [0, 13, 18, 9, 7, 6, 1, 0, 10]
        // Stop bits              --  --  -
        // Iter 3 (step = 4)  [0, 19, 19, 9, 7, 6, 1, 0, 10]
        // Stop bits
        // Iter 4 (step = 8)  [0, 19, 19, 9, 7, 6, 1, 0, 10]

        let exepcted_output = vec![0_u128, 19, 19, 9, 7, 6, 1, 0, 10];

        let num_rows = input[0].len();
        let mut shares = [
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
        ];

        for x in input {
            let (h0, (h1, h2)): (Vec<_>, (Vec<_>, Vec<_>)) = x
                .into_iter()
                .map(|y| {
                    let ss = share(Fp31::from(y), &mut rng);
                    (ss[0], (ss[1], ss[2]))
                })
                .unzip();
            shares[0].push(h0);
            shares[1].push(h1);
            shares[2].push(h2);
        }

        let acc0 = Attribute::new(&context[0], AttributionModel::LastTouch);
        let acc1 = Attribute::new(&context[1], AttributionModel::LastTouch);
        let acc2 = Attribute::new(&context[2], AttributionModel::LastTouch);
        let h0_future = acc0.execute(&shares[0]);
        let h1_future = acc1.execute(&shares[1]);
        let h2_future = acc2.execute(&shares[2]);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), num_rows);
        assert_eq!(result.1.len(), num_rows);
        assert_eq!(result.2.len(), num_rows);

        (0..(result.0.len())).for_each(|i| {
            let v = validate_and_reconstruct((result.0[i], result.1[i], result.2[i]));
            assert_eq!(v.as_u128(), exepcted_output[i]);
        });
    }
}
