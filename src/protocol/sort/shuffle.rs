use crate::helpers::prss::PrssSpace;
use crate::helpers::Direction;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[allow(dead_code)]
pub struct Shuffle {}

impl Shuffle {
    /// This implements Fisher Yates shuffle described here <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle>
    #[allow(dead_code)]
    fn generate_random_permutation(
        batchsize: usize,
        direction: Direction,
        index: u128,
        prss: &PrssSpace,
    ) -> Vec<usize> {
        let mut permutation: Vec<usize> = (0..batchsize).collect();
        let seed = prss.generate_values(index);

        let seed_bytes = if direction == Direction::Left {
            seed.0.to_le_bytes()
        } else {
            seed.1.to_le_bytes()
        };
        // Chacha8Rng expects a [u8;32] seed whereas prss returns a u128 number.
        // We are using two spaces to generate indexes and concatenating them
        let mut seed: [u8; 32] = [0; 32];
        let (first_half, second_half) = seed.split_at_mut(16);
        first_half.copy_from_slice(&seed_bytes[..16]);
        second_half.copy_from_slice(&seed_bytes[..16]);
        permutation.shuffle(&mut ChaCha8Rng::from_seed(seed));
        permutation
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        helpers::Direction,
        test_fixture::{make_participants, TestStep},
    };
    use rand::{rngs::mock::StepRng, Rng};

    use super::Shuffle;

    #[test]
    fn random_sequence_generated() {
        let mut rand = StepRng::new(1, 1);
        let batchsize = 10000;
        let (p1, p2, p3) = make_participants();

        let index = rand.gen::<u128>();
        let sequence1left = Shuffle::generate_random_permutation(
            batchsize,
            Direction::Left,
            index,
            &p1[TestStep::Shuffle],
        );
        let mut sequence1right = Shuffle::generate_random_permutation(
            batchsize,
            Direction::Right,
            index,
            &p1[TestStep::Shuffle],
        );

        let sequence2left = Shuffle::generate_random_permutation(
            batchsize,
            Direction::Left,
            index,
            &p2[TestStep::Shuffle],
        );
        let mut sequence2right = Shuffle::generate_random_permutation(
            batchsize,
            Direction::Right,
            index,
            &p2[TestStep::Shuffle],
        );

        let sequence3left = Shuffle::generate_random_permutation(
            batchsize,
            Direction::Left,
            index,
            &p3[TestStep::Shuffle],
        );
        let mut sequence3right = Shuffle::generate_random_permutation(
            batchsize,
            Direction::Right,
            index,
            &p3[TestStep::Shuffle],
        );

        let expected_numbers: Vec<usize> = (0..batchsize).collect();
        assert_eq!(sequence1right, sequence2left);
        assert_eq!(sequence2right, sequence3left);
        assert_eq!(sequence3right, sequence1left);

        // Due to less randomness, the below three asserts can fail. However, the chance of failure is
        // 1/18Quintillian (a billion billion since u64 is used to generate randomness)! Hopefully we should not hit that
        assert_ne!(sequence1left, sequence1right);
        assert_ne!(sequence2left, sequence2right);
        assert_ne!(sequence3left, sequence3right);

        sequence1right.sort_unstable();
        sequence2right.sort_unstable();
        sequence3right.sort_unstable();

        assert_eq!(sequence1right, expected_numbers);
        assert_eq!(sequence2right, expected_numbers);
        assert_eq!(sequence3right, expected_numbers);
    }
}
