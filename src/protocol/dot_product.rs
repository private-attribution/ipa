///
/// This protocol is an extension of the CHIKP multiplication protocol described in the paper:
/// "High-Throughput Secure AES Computation" (High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018)
/// by Koji Chida, Koki Hamada, Dai Ikarashi, Ryo Kikuchi and Benny Pinkas
/// <https://dl.acm.org/doi/10.1145/3267973.3267977>
///
/// The extension allows for the computation of the sum of multiple multiplications (in other words, a dot-product operation)
/// at the communication cost of a single multiplication.
///
/// This extension is summarized in the paper:
/// "Fast Large-Scale Honest-Majority MPC for Malicious Adversaries"
/// by Koji Chida, Daniel Genkin, Koki Hamada, Dai Ikarashi, Ryo Kikuchi, Yehuda Lindell, and Ariel Nof
/// <https://link.springer.com/content/pdf/10.1007/978-3-319-96878-0_2.pdf>
///
/// In that paper, this functionality is called `F_product` and
/// an instantiation for Replciated Secret Sharing is provided in section 6.1 on page 27
///
/// To summarize the CHIKP protocol:
/// each helper computes `u_i+1 = (s_i + s_i+1) * (t_i + t_i+1) - s_i+1 * t_i+1`
/// It then randomizes this share with randomness that it shares with the
/// helper to its left, and sends it to the helper to its right,
/// and receives `u_i` from the helper to its left.
/// Each helper then defines the pair `(u_i, u_i+1)` as its shares of the output.
///
/// (Note it is equivalent to compute `u_i+1 = s_i * t_i + s_i+1 * t_i + s_i * t_i+1`,
/// but this requires three multiplications instead of two. Assuming multiplying field elements is
/// significantly more costly (in CPU terms) than addition, this is less efficient to compute)
///
/// The key observation that makes this protocol work, is that each helper can compute many `u_i+1` values
/// from many multiplications, sum them all together, randomize them with correlated randomness, and can
/// send this single field value to the next helper. The result will be a replicated secret sharing of the
/// dot-product of the two vectors.
///
pub mod stream {
    use crate::{
        error::BoxError,
        field::Field,
        helpers::{fabric::Network, Direction},
        protocol::{context::ProtocolContext, RecordId},
        secret_sharing::Replicated,
    };
    use futures::stream::StreamExt; // for `next`
    use futures::Stream;
    use std::pin::Pin;

    use serde::{Deserialize, Serialize};

    /// A message sent by each helper when they've computed one share of the result
    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct UValue<F> {
        u: F,
    }

    type PairOfShares<F> = (Replicated<F>, Replicated<F>);

    ///
    /// Consumes the input stream of pairs of replicated secret shares and
    /// for each pair, multiplies them, and accumulates the result in a running sum.
    /// once all the values in the stream are consumed, it randomizes the sum with
    /// randomness it shares with the helper to the left, and sends to the right.
    /// It receives a randomized sum from the helper to its left, and is now in
    /// possession of a replicated secret sharing of the dot-product of the two
    /// streaming vectors of replicated secret shares.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    #[allow(dead_code)]
    pub async fn accumulate_dot_product<F: Field, N: Network>(
        ctx: ProtocolContext<'_, N>,
        record_id: RecordId,
        mut input_stream: Pin<Box<dyn Stream<Item = PairOfShares<F>>>>,
    ) -> Result<Replicated<F>, BoxError> {
        let prss = &ctx.prss();
        let (s_left, s_right): (F, F) = prss.generate_fields(record_id);

        let mut u_right = s_right - s_left;

        while let Some(item) = input_stream.next().await {
            let (a_share, b_share) = item;

            let (a_left, a_right) = a_share.as_tuple();
            let (b_left, b_right) = b_share.as_tuple();
            u_right += (a_left + a_right) * (b_left + b_right) - a_right * b_right;
        }

        // send our `u_i+1` value to the helper on the right
        let channel = ctx.mesh();
        channel
            .send(
                channel.identity().peer(Direction::Right),
                record_id,
                UValue { u: u_right },
            )
            .await?;

        // receive `u_i` value from helper to the left
        let UValue { u: u_left } = channel
            .receive(channel.identity().peer(Direction::Left), record_id)
            .await?;

        Ok(Replicated::new(u_left, u_right))
    }

    #[cfg(test)]
    mod tests {
        use crate::error::BoxError;
        use crate::field::Field;
        use crate::field::Fp31;
        use crate::protocol::dot_product::stream::accumulate_dot_product;
        use crate::protocol::{QueryId, RecordId};
        use crate::test_fixture::{
            logging, make_contexts, make_world, share, validate_and_reconstruct,
        };
        use futures_util::stream;
        use proptest::prelude::Rng;

        #[tokio::test]
        async fn supports_stream_of_secret_shares() -> Result<(), BoxError> {
            logging::setup();

            let mut rng = rand::thread_rng();

            let mut vec1 = Vec::with_capacity(100);
            let mut vec2 = Vec::with_capacity(100);
            let mut vec3 = Vec::with_capacity(100);

            let mut correct_answer = Fp31::ZERO;

            for _ in 0..100 {
                let a_i = Fp31::from(rng.gen::<u128>());
                let b_i = Fp31::from(rng.gen::<u128>());
                let a_i_shares = share(a_i, &mut rng);
                let b_i_shares = share(b_i, &mut rng);
                vec1.push((a_i_shares[0], b_i_shares[0]));
                vec2.push((a_i_shares[1], b_i_shares[1]));
                vec3.push((a_i_shares[2], b_i_shares[2]));
                correct_answer += a_i * b_i;
            }

            // setup helpers
            let world = make_world(QueryId);
            let context = make_contexts(&world);
            let record_id = RecordId::from(0);
            let step = "some_step".to_string();

            let result_shares = tokio::try_join!(
                accumulate_dot_product(
                    context[0].narrow(&step),
                    record_id,
                    Box::pin(stream::iter(vec1)),
                ),
                accumulate_dot_product(
                    context[1].narrow(&step),
                    record_id,
                    Box::pin(stream::iter(vec2)),
                ),
                accumulate_dot_product(
                    context[2].narrow(&step),
                    record_id,
                    Box::pin(stream::iter(vec3)),
                ),
            )
            .unwrap();

            let result = validate_and_reconstruct(result_shares);

            assert_eq!(result, correct_answer);

            Ok(())
        }
    }
}
