use super::carries::Carries;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{context::Context, RecordId};
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
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, Error> {
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
    use crate::protocol::context::Context;
    use crate::{
        error::BoxError,
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{bits_to_field, shared_bits, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng, Rng};

    /// From `Vec<[Replicated<F>; 3]>`, create `Vec<Replicated<F>>` taking the `i`'th share per row
    fn transpose<F: Field>(x: &[[Replicated<F>; 3]], i: usize) -> Vec<Replicated<F>> {
        x.iter().map(|x| x[i].clone()).collect::<Vec<_>>()
    }

    #[allow(clippy::many_single_char_names)]
    async fn bitwise_sum<F: Field>(a: F, b: F) -> Result<Vec<F>, BoxError>
    where
        Standard: Distribution<F>,
    {
        let world = TestWorld::new(QueryId);
        let ctx = world.contexts::<F>();
        let mut rand = StepRng::new(1, 1);

        let a_bits = shared_bits(a, &mut rand);
        let b_bits = shared_bits(b, &mut rand);
        let l = a_bits.len();

        let step = "BitwiseSum_Test";
        let result = try_join_all(vec![
            BitwiseSum::execute(
                ctx[0].narrow(step),
                RecordId::from(0_u32),
                &transpose(&a_bits, 0),
                &transpose(&b_bits, 0),
            ),
            BitwiseSum::execute(
                ctx[1].narrow(step),
                RecordId::from(0_u32),
                &transpose(&a_bits, 1),
                &transpose(&b_bits, 1),
            ),
            BitwiseSum::execute(
                ctx[2].narrow(step),
                RecordId::from(0_u32),
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
    pub async fn fp31_basic() -> Result<(), BoxError> {
        let c = Fp31::from;

        assert_eq!(c(0_u8), bits_to_field(&bitwise_sum(c(0), c(0)).await?));
        assert_eq!(c(1), bits_to_field(&bitwise_sum(c(0), c(1)).await?));
        assert_eq!(c(1), bits_to_field(&bitwise_sum(c(1), c(0)).await?));
        assert_eq!(c(2), bits_to_field(&bitwise_sum(c(1), c(1)).await?));

        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime_basic() -> Result<(), BoxError> {
        let c = Fp32BitPrime::from;

        assert_eq!(c(0_u32), bits_to_field(&bitwise_sum(c(0), c(0)).await?));
        assert_eq!(c(1), bits_to_field(&bitwise_sum(c(0), c(1)).await?));
        assert_eq!(c(1), bits_to_field(&bitwise_sum(c(1), c(0)).await?));
        assert_eq!(c(2), bits_to_field(&bitwise_sum(c(1), c(1)).await?));
        assert_eq!(
            c(2_147_483_648_u32),
            bits_to_field(&bitwise_sum(c(2_147_483_647), c(1)).await?)
        );
        assert_eq!(
            c(4_294_967_290),
            bits_to_field(&bitwise_sum(c(2_147_483_645), c(2_147_483_645)).await?)
        );
        assert_eq!(
            c(0),
            bits_to_field(&bitwise_sum(c(2_147_483_645), c(2_147_483_646)).await?)
        );

        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime_random() -> Result<(), BoxError> {
        let c = Fp32BitPrime::from;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let a = c(rng.gen::<u128>());
            let b = c(rng.gen());
            assert_eq!(a + b, bits_to_field(&bitwise_sum(a, b).await?));
        }

        Ok(())
    }
}
