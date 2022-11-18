use super::carries::Carries;
use crate::error::BoxError;
use crate::ff::Field;
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;

/// This is an implementation of Bitwise Sum on bitwise-shared numbers.
///
/// `BitwiseSum` takes inputs `[a]_B = ([a_0]_p,...,[a_(l-1)]_p)` where
/// `a_0,...,a_(l-1) ∈ {0,1} ⊆ F_p` and `[b]_B = ([b_0]_p,...,[b_(l-1)]_p)` where
/// `b_0,...,b_(l-1) ∈ {0,1} ⊆ F_p`, then computes `[d]_B = ([d_0]_p,...,[d_l]_p)`
/// of `a + b`.
///
/// Note that the index notation of the inputs is `0..l-1`, whereas the output
/// index notation is `0..l`. This means that the output of this protocol will be
/// "`l+1`"-bit long bitwise secret shares, where `l = |[a]_B|`.
///
/// This protocol calls `Carries` as its sub-protocol to get `c_i ∈ {0, 1}`
/// where `c_i = 1` iff `Σ (2^j * (a_j + b_j)) > 2_i` where `j=0..i-1`. We can
/// then use `[c_i]` to compute a bitwise sharing of sum `[a]_B` and `[b]_b`.
///
/// All computations other than `Carries` are done locally, so the cost of this
/// protocol equals `Carries`' cost.
///
/// 6.2 Bitwise Sum
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct BitwiseSum {}

impl BitwiseSum {
    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        debug_assert_eq!(a.len(), b.len(), "Length of the input bits must be equal");
        let l = a.len();

        // Step 1. Get a bitwise sharing of the carries
        let c = Carries::execute(ctx.narrow(&Step::Carries), record_id, a, b).await?;

        // Step 2. `[d_0] = [a_0] + [b_0] - 2[c_1]`
        // The paper refers `[c]_b` as `([c_1],...[c_l])`; the starting index is 1;
        // therefore, `[c_1]` is the first element, `c[0]`, in the code.
        let mut d = Vec::with_capacity(l);
        d.push(a[0].clone() + &b[0] - &(c[0].clone() * F::from(2)));

        // Step 3. `[d_l] = [c_l]`
        // Step 4. for `i=1..l-1`, `[d_i] = [a_i] + [b_i] + [c_i] - 2[c_(i+1)]`
        //
        // In the paper, the output of BIT-ADD is `l + 1` long, where `l` is
        // the length of the inputs `a` and `b`. So, if we are working with a
        // 32-bit long field, the output of this protocol will be 33-bit long
        // bitwise shares.
        for i in 1..l {
            d.push(a[i].clone() + &b[i] + &c[i - 1] - &(c[i].clone() * F::from(2)));
        }
        d.push(c[l - 1].clone());

        Ok(d)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    Carries,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::Carries => "carries",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitwiseSum;
    use crate::{
        error::BoxError,
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::ProtocolContext, QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{
            make_contexts, make_world, shared_bits, transpose, validate_and_reconstruct, TestWorld,
        },
    };
    use futures::future::try_join_all;
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng, Rng};

    // `Carries<Fp32BitPrime>` takes ~0.4sec...
    const TEST_TRIES: u32 = 5;

    /// Take a slice of bits in `{0,1} ⊆ F_p`, and reconstruct the integer in `F_p`
    fn bits_to_field<F: Field>(x: &[F]) -> F {
        #[allow(clippy::cast_possible_truncation)]
        let v = x
            .iter()
            .enumerate()
            .fold(0, |acc, (i, &b)| acc + 2_u128.pow(i as u32) * b.as_u128());
        F::from(v)
    }

    #[allow(clippy::many_single_char_names)]
    async fn bitwise_sum<F: Field>(
        ctx: [ProtocolContext<'_, Replicated<F>, F>; 3],
        record_id: RecordId,
        a: F,
        b: F,
    ) -> Result<Vec<F>, BoxError>
    where
        Standard: Distribution<F>,
    {
        let [c0, c1, c2] = ctx;
        let mut rand = StepRng::new(1, 1);

        let a_bits = shared_bits(a, &mut rand);
        let b_bits = shared_bits(b, &mut rand);
        let l = a_bits.len();

        // Execute
        let result = try_join_all(vec![
            BitwiseSum::execute(
                c0.bind(record_id),
                record_id,
                &transpose(&a_bits, 0),
                &transpose(&b_bits, 0),
            ),
            BitwiseSum::execute(
                c1.bind(record_id),
                record_id,
                &transpose(&a_bits, 1),
                &transpose(&b_bits, 1),
            ),
            BitwiseSum::execute(
                c2.bind(record_id),
                record_id,
                &transpose(&a_bits, 2),
                &transpose(&b_bits, 2),
            ),
        ])
        .await
        .unwrap();

        // `result` is comprised of three bitwise-sharings of `a + b`
        let sum = (0..result[0].len())
            .map(|i| validate_and_reconstruct(&result[0][i], &result[1][i], &result[2][i]))
            .collect::<Vec<_>>();

        // Output's bit length should be `input.len() + 1`
        assert_eq!(l + 1, sum.len());

        Ok(sum)
    }

    #[tokio::test]
    pub async fn fp31() -> Result<(), BoxError> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        for i in 0..TEST_TRIES {
            let (a, b) = (rng.gen::<Fp31>(), rng.gen::<Fp31>());
            assert_eq!(
                a + b,
                bits_to_field(
                    &bitwise_sum(
                        [c0.clone(), c1.clone(), c2.clone()],
                        RecordId::from(i),
                        a,
                        b
                    )
                    .await?
                )
            );
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() -> Result<(), BoxError> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp32BitPrime>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        for i in 0..TEST_TRIES {
            let (a, b) = (rng.gen::<Fp32BitPrime>(), rng.gen::<Fp32BitPrime>());
            assert_eq!(
                a + b,
                bits_to_field(
                    &bitwise_sum(
                        [c0.clone(), c1.clone(), c2.clone()],
                        RecordId::from(i),
                        a,
                        b
                    )
                    .await?
                )
            );
        }
        Ok(())
    }
}
