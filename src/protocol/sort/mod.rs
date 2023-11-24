pub mod apply_sort;
pub mod bit_permutation;
pub mod generate_permutation;
pub mod generate_permutation_opt;

mod compose;
mod multi_bit_permutation;
mod secureapplyinv;
mod shuffle;

use ipa_macros::Step;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, step::BitOpStep, BasicProtocols, RecordId},
    secret_sharing::{BitDecomposed, Linear as LinearSecretSharing, SecretSharing},
};

#[derive(Step)]
pub(crate) enum SortStep {
    ModulusConversion,
    BitPermutation,
    Compose,
    ShuffleRevealPermutation,
    SortKeys,
    #[dynamic(64)]
    MultiApplyInv(u32),
}

#[derive(Step, Clone, Copy)]
pub(crate) enum ShuffleStep {
    Shuffle1,
    Shuffle2,
    Shuffle3,
}

#[derive(Step)]
pub(crate) enum ApplyInvStep {
    ShuffleInputs,
}

#[derive(Step)]
pub(crate) enum ComposeStep {
    UnshuffleRho,
}

#[derive(Step)]
pub(crate) enum ShuffleRevealPermutationStep {
    Generate,
    Reveal,
    Shuffle,
}

#[derive(Step)]
pub(crate) enum ReshareStep {
    RandomnessForValidation,
    ReshareRx,
}

/// Convert a bitwise representation of a number into a one-hot encoding of that number.
/// That is, an array of value of 1 at the index corresponding to the value of the number,
/// and a 0 at all other indices.
///
/// This function accepts a sequence of N secret-shared bits, with the least significant bit at index 0.
/// When considered as a bitwise representation of an N-bit unsigned number, there are exactly
/// `2^N` possible values this could have.
///
/// # Errors
/// If any multiplication fails, or if the record is too long (e.g. more than 64 multiplications required)
pub async fn bitwise_to_onehot<F, C, S>(
    ctx: C,
    record_idx: usize,
    number: &[S],
) -> Result<BitDecomposed<S>, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let num_bits = number.len();
    let precomputed_combinations =
        generate_all_combinations(ctx, record_idx, number, num_bits).await?;

    // This loop just iterates over all the possible values this N-bit input could potentially represent
    // and checks if the bits are equal to this value. It does so by computing a linear combination of the
    // pre-computed coefficients.
    //
    // Observe that whether a given precomputed coefficient contributes to a
    // given equality check follows a Sierpiński triangle
    // https://en.wikipedia.org/wiki/Sierpi%C5%84ski_triangle#/media/File:Multigrade_operator_AND.svg.
    //
    // For example, for a three bit value, we have the following:
    // 0: 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1
    // 1: 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1
    // 2: 0 | 0 | 1 | 1 | 0 | 0 | 1 | 1
    // 3: 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1
    // 4: 0 | 0 | 0 | 0 | 1 | 1 | 1 | 1
    // 5: 0 | 0 | 0 | 0 | 0 | 1 | 0 | 1
    // 6: 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1
    // 7: 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1
    //
    // This can be computed from row (i) and column (j) indices with i & j == i
    //
    // The sign of the inclusion is less obvious, but we discovered that this
    // can be found by taking the same row (i) and column (j) indices:
    // 1. Invert the row index and bitwise AND the indices: a = !i & j
    // 2. Count the number of bits that are set: b = a.count_ones()
    // 3. An odd number means a positive coefficient; an odd number means a negative.
    //
    // For example, for a three bit value, step 1 produces (in binary):
    // 0: 000 | 001 | 010 | 011 | 100 | 101 | 110 | 111
    // 1: 000 | 000 | 010 | 010 | 100 | 100 | 110 | 110
    // 2: 000 | 001 | 000 | 001 | 100 | 101 | 100 | 101
    // 3: 000 | 000 | 000 | 000 | 100 | 100 | 100 | 100
    // 4: 000 | 001 | 010 | 011 | 000 | 001 | 010 | 011
    // 5: 000 | 000 | 010 | 010 | 000 | 000 | 010 | 010
    // 6: 000 | 001 | 000 | 001 | 000 | 001 | 000 | 001
    // 7: 000 | 000 | 000 | 000 | 000 | 000 | 000 | 000
    //
    // Where 000, 101, 011, and 110 mean positive contributions, and
    // 001, 010, 100, and 111 mean negative contributions.
    //
    // 0: + | - | - | + | - | + | + | -
    // 1: . | + | . | - | . | - | . | +
    // 2: . | . | + | - | . | . | - | +
    // 3: . | . | . | + | . | . | . | -
    // 4: . | . | . | . | + | - | - | +
    // 5: . | . | . | . | . | + | . | -
    // 6: . | . | . | . | . | . | + | -
    // 7: . | . | . | . | . | . | . | +
    Ok(BitDecomposed::decompose(1 << num_bits, |i| {
        // Small optimization: skip the blank area and start with the first "+".
        let mut check = precomputed_combinations[i].clone();
        for (j, combination) in precomputed_combinations.iter().enumerate().skip(i + 1) {
            if (i & j) == i {
                if (!i & j).count_ones() & 1 == 1 {
                    check -= combination;
                } else {
                    check += combination;
                }
            }
        }
        check
    }))
}

//
// Every equality check can be computed as a linear combination of coefficients.
// For example, if we are given a 3-bit number `[x_3, x_2, x_1]`,
// we can check if it is equal to 4, by computing:
// $x_3(1-x_2)(1-x_1)$,
// which expands to:
// $x_3 - x_2*x_3 - x_1*x_3 + x_1*x_2*x_3$
//
// Since we need to check all possible values, it makes sense to pre-compute all
// of the coefficients that are used across all of these equality checks. In this way,
// we can minimize the total number of multiplications needed.
//
// We must pre-compute all combinations of bit values. The following loop does so.
// It does so by starting with the array `[1]`.
// The next step is to multiply this by `x_1` and append it to the end of the array.
// Now the array is `[1, x_1]`.
// The next step is to multiply all of these values by `x_2` and append them to the end of the array.
// Now the array is `[1, x_1, x_2, x_1*x_2]`
// The next step is to mulitply all of these values of `x_3` and append them to the end of the array.
// Now the array is `[1, x_1, x_2, x_1*x_2, x_3, x_1*x_3, x_2*x_3, x_1*x_2*x_3]`
// This process continues for as many steps as there are bits of input.
//
// Operation complexity of this function is `2^n-n-1` where `n` is the number of bits.
// Circuit depth is equal to `n-2`.
// This gets inefficient very quickly as a result.
async fn generate_all_combinations<F, C, S>(
    ctx: C,
    record_idx: usize,
    input: &[S],
    num_bits: usize,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: SecretSharing<F> + BasicProtocols<C, F>,
{
    let record_id = RecordId::from(record_idx);
    let mut all_combinations = Vec::with_capacity(1 << num_bits);
    all_combinations.push(S::share_known_value(&ctx, F::ONE));
    for (bit_idx, bit) in input.iter().enumerate() {
        let step = 1 << bit_idx;
        // Concurrency needed here because we are operating on different bits for the same record.
        let mut multiplication_results =
            ctx.parallel_join(all_combinations.iter().skip(1).enumerate().map(
                |(j, combination)| {
                    let child_idx = j + step;
                    combination.multiply(bit, ctx.narrow(&BitOpStep::from(child_idx)), record_id)
                },
            ))
            .await?;
        all_combinations.push(bit.clone());
        all_combinations.append(&mut multiplication_results);
    }
    Ok(all_combinations)
}

#[cfg(all(test, unit_test))]
mod test {
    use futures::future::join4;

    use crate::{
        ff::{Field, Fp31},
        protocol::{context::Context, sort::bitwise_to_onehot},
        secret_sharing::{BitDecomposed, SharedValue},
        seq_join::SeqJoin,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    async fn check_onehot(bits: u32) {
        let world = TestWorld::default();

        // Construct bitwise sharings of all values from 0 to 2^BITS-1.
        let input = (0..(1 << bits)).map(move |i| {
            BitDecomposed::decompose(bits, |j| {
                Fp31::truncate_from(u128::from((i & (1 << j)) == (1 << j)))
            })
        });

        let result = world
            .semi_honest(input, |ctx, m_shares| async move {
                let ctx = ctx.set_total_records(m_shares.len());
                ctx.try_join(
                    m_shares
                        .iter()
                        .enumerate()
                        .map(|(i, n)| bitwise_to_onehot(ctx.clone(), i, n)),
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        for (i, onehot) in result.into_iter().enumerate() {
            for (j, v) in onehot.into_iter().enumerate() {
                if i == j {
                    assert_eq!(Fp31::ONE, v);
                } else {
                    assert_eq!(Fp31::ZERO, v);
                }
            }
        }
    }

    #[tokio::test]
    async fn several_onehot() {
        _ = join4(
            check_onehot(1),
            check_onehot(2),
            check_onehot(3),
            check_onehot(4),
        )
        .await;
    }
}
