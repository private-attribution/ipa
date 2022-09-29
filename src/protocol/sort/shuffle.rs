use crate::helpers::prss::PrssSpace;

#[allow(dead_code)]

pub struct Shuffle {}

impl Shuffle {
    /// The Fisher–Yates shuffle is an algorithm for generating a random permutation of a finite
    /// sequence—in plain terms, the algorithm shuffles the sequence. The algorithm effectively
    /// puts all the elements into a hat; it continually determines the next element by randomly
    /// drawing an element from the hat until no elements remain. The algorithm produces an unbiased
    /// permutation: every permutation is equally likely. This algorithm takes time proportional to
    /// the number of items being shuffled and shuffles them in place.
    #[allow(dead_code)]
    fn generate_random_sequence(
        batchsize: usize,
        random_value: u128,
        left_permute: bool,
        prss: &PrssSpace,
    ) -> Vec<usize> {
        let mut permutation: Vec<usize> = (0..batchsize).collect();
        (1..batchsize).rev().for_each(|i| {
            let location = if left_permute {
                (prss.generate_values(random_value).0 as usize) % i
            } else {
                (prss.generate_values(random_value).1 as usize) % i
            };
            permutation.swap(i, location);
        });
        permutation
    }
}

#[cfg(test)]
mod tests {
    use crate::test_fixture::{make_participants, TestStep};
    use rand::{rngs::mock::StepRng, Rng};

    use super::Shuffle;

    #[test]
    fn random_sequence_generated() {
        let mut rand = StepRng::new(1, 1);
        let batchsize = 10;
        let (p1, p2, p3) = make_participants();
        let random_value = rand.gen::<u128>();
        let sequence1left = Shuffle::generate_random_sequence(
            batchsize,
            random_value,
            true,
            &p1[TestStep::Shuffle],
        );
        let mut sequence1right = Shuffle::generate_random_sequence(
            batchsize,
            random_value,
            false,
            &p1[TestStep::Shuffle],
        );

        let sequence2left = Shuffle::generate_random_sequence(
            batchsize,
            random_value,
            true,
            &p2[TestStep::Shuffle],
        );
        let mut sequence2right = Shuffle::generate_random_sequence(
            batchsize,
            random_value,
            false,
            &p2[TestStep::Shuffle],
        );

        let sequence3left = Shuffle::generate_random_sequence(
            batchsize,
            random_value,
            true,
            &p3[TestStep::Shuffle],
        );
        let mut sequence3right = Shuffle::generate_random_sequence(
            batchsize,
            random_value,
            false,
            &p3[TestStep::Shuffle],
        );

        let expected_numbers: Vec<usize> = (0..batchsize).collect();
        assert_eq!(sequence1right, sequence2left);
        assert_eq!(sequence2right, sequence3left);
        assert_eq!(sequence3right, sequence1left);

        sequence1right.sort_unstable();
        sequence2right.sort_unstable();
        sequence3right.sort_unstable();

        assert_eq!(sequence1right, expected_numbers);
        assert_eq!(sequence2right, expected_numbers);
        assert_eq!(sequence3right, expected_numbers);
    }
}
