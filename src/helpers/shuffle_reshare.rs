use crate::{field::Fp31, modulus_convert::ReplicatedFp31SecretSharing, prss::Participant};

fn helper_get_shuffled_locations(
    participant: &Participant,
    seed: u128,
    batchsize: usize,
) -> (Vec<usize>, Vec<usize>) {
    fn generate_permutation(
        participant: &Participant,
        batchsize: usize,
        random_value: u128,
        permute_for_right: bool,
    ) -> Vec<usize> {
        let mut permutation: Vec<usize> = (0..batchsize).collect();
        // Fisher–Yates shuffle
        (1..batchsize).rev().for_each(|i| {
            let location = if permute_for_right {
                (participant.generate_values(random_value).1 as usize) % i
            } else {
                (participant.generate_values(random_value).0 as usize) % i
            };
            permutation.swap(i, location);
        });
        permutation
    }
    let random_values = participant.generate_values(seed);
    (
        generate_permutation(participant, batchsize, random_values.0, false),
        generate_permutation(participant, batchsize, random_values.1, true),
    )
}

#[must_use]
pub fn helper_shuffle_shares(
    participant: &Participant,
    seed: u128,
    shares: &[ReplicatedFp31SecretSharing],
    shuffle_on_right_locations: bool,
) -> Vec<ReplicatedFp31SecretSharing> {
    let locations = if shuffle_on_right_locations {
        helper_get_shuffled_locations(participant, seed, shares.len()).1
    } else {
        helper_get_shuffled_locations(participant, seed, shares.len()).0
    };
    let mut shuffle = Vec::with_capacity(shares.len());
    for iter in locations {
        shuffle.push(shares[iter]);
    }
    shuffle
}

#[must_use]
pub fn helper_get_reshares(
    participant: &Participant,
    shares: Vec<ReplicatedFp31SecretSharing>,
    random_offset_seed: u128,
    reshare_right: bool,
) -> (Vec<Fp31>, Vec<Fp31>) {
    let mut reshare = Vec::new();
    let mut share = Vec::new();
    for iter in shares {
        let random_offset = participant.generate_values(random_offset_seed);
        if reshare_right {
            reshare.push(iter.1 + Fp31::from(random_offset.0));
            share.push(iter.0);
        } else {
            reshare.push(iter.0 - Fp31::from(random_offset.1));
            share.push(iter.1);
        }
    }
    (reshare, share)
}

#[must_use]
pub fn apply_shares(left_share: &[Fp31], right_share: &[Fp31]) -> Vec<ReplicatedFp31SecretSharing> {
    left_share
        .iter()
        .zip(right_share.iter())
        .map(|(l, r)| ReplicatedFp31SecretSharing::construct(*l, *r))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        field::Fp31,
        helpers::shuffle_reshare::{
            apply_shares, helper_get_reshares, helper_get_shuffled_locations, helper_shuffle_shares,
        },
        modulus_convert::ReplicatedFp31SecretSharing,
        prss::{Participant, ParticipantSetup},
    };
    use itertools::izip;
    use rand::{thread_rng, Rng};

    // Shuffling Protocol
    // This is broken in three parts - Shuffle, reshare and apply reshares
    fn shuffling_protocol(
        participants: &[Participant],
        seed: u128,
        shares: &[Vec<ReplicatedFp31SecretSharing>],
    ) -> Vec<Vec<ReplicatedFp31SecretSharing>> {
        let mut shuffled_shares = shares.to_vec();

        (0_usize..3).for_each(|i| {
            let idx = (i % 3, (i + 1) % 3, (i + 2) % 3);
            let random_offset_seed = thread_rng().gen_range(0..u128::MAX);

            // TODO This should happen on Pi for a given round
            // Shuffle
            let shares1 = helper_shuffle_shares(&participants[idx.0], seed, &shares[idx.0], false);
            // Reshare
            // TODO This should happen on Pi for a given round
            let (reshare1_right, share1_left) =
                helper_get_reshares(&participants[idx.0], shares1, random_offset_seed, true);
            // Apply on each share
            let shares1 = apply_shares(&share1_left, &reshare1_right);

            // TODO This should happen on Pi+2 for a given round
            // Shuffle
            let shares3 = helper_shuffle_shares(&participants[idx.2], seed, &shares[idx.2], true);
            // Reshare
            let (reshare3_left, share3_right) =
                helper_get_reshares(&participants[idx.2], shares3, random_offset_seed, false);
            // Apply on each share
            let shares3 = apply_shares(&reshare3_left, &share3_right);

            // TODO This should happen on Pi+1 for a given round
            // Apply on each share
            let shares2 = apply_shares(&reshare1_right, &reshare3_left);

            (0..shares1.len()).for_each(|i| {
                assert_eq!(
                    shares1[i].0 + shares2[i].0 + shares3[i].0,
                    shares1[i].1 + shares2[i].1 + shares3[i].1
                );
                println!(
                    "shares{:?} : Sum: {:?} , {:?}, {:?}, {:?}",
                    i,
                    shares1[i].1 + shares2[i].1 + shares3[i].1,
                    shares1[i].0,
                    shares2[i].0,
                    shares3[i].0
                );
            });
            shuffled_shares[idx.0] = shares1;
            shuffled_shares[idx.1] = shares2;
            shuffled_shares[idx.2] = shares3;
        });

        // At this stage, we can reveal the sort locations since all the shares are shuffled
        shuffled_shares
    }

    /// Generate three participants.
    /// p1 is left of p2, p2 is left of p3, p3 is left of p1...
    fn make_three() -> (Participant, Participant, Participant) {
        let mut r = thread_rng();
        let setup1 = ParticipantSetup::new(&mut r);
        let setup2 = ParticipantSetup::new(&mut r);
        let setup3 = ParticipantSetup::new(&mut r);
        let (pk1_l, pk1_r) = setup1.public_keys();
        let (pk2_l, pk2_r) = setup2.public_keys();
        let (pk3_l, pk3_r) = setup3.public_keys();

        let p1 = setup1.setup(&pk3_r, &pk2_l);
        let p2 = setup2.setup(&pk1_r, &pk3_l);
        let p3 = setup3.setup(&pk2_r, &pk1_l);

        (p1, p2, p3)
    }

    #[test]
    fn shuffled_locations() {
        let (p1, p2, p3) = make_three();
        let batchsize = 20;
        let seed = thread_rng().gen_range(0..u128::MAX);
        let (p1_l, p1_r) = helper_get_shuffled_locations(&p1, seed, batchsize);
        let (p2_l, p2_r) = helper_get_shuffled_locations(&p2, seed, batchsize);
        let (p3_l, p3_r) = helper_get_shuffled_locations(&p3, seed, batchsize);
        assert_eq!(p1_l, p3_r);
        assert_eq!(p2_l, p1_r);
        assert_eq!(p3_l, p2_r);
    }

    #[test]
    fn apply_shuffle_on_shares() {
        fn convert_vec_replicated_shares(
            input: Vec<(u128, u128)>,
        ) -> Vec<ReplicatedFp31SecretSharing> {
            let mut replicated_share_vec = Vec::new();
            for iter in input {
                replicated_share_vec.push(ReplicatedFp31SecretSharing::construct(
                    Fp31::from(iter.0),
                    Fp31::from(iter.1),
                ));
            }
            replicated_share_vec
        }
        let input1 = [
            (22_u128, 11_u128),
            (17, 12),
            (18, 16),
            (19, 11),
            (20, 11),
            (21, 11),
        ];
        let input2 = [
            (11_u128, 3_u128),
            (12, 3),
            (16, 3),
            (11, 3),
            (11, 3),
            (11, 3),
        ];
        let input3 = [
            (3_u128, 22_u128),
            (3, 17),
            (3, 18),
            (3, 19),
            (3, 20),
            (3, 21),
        ];

        let shares = vec![
            convert_vec_replicated_shares(input1.to_vec()),
            convert_vec_replicated_shares(input2.to_vec()),
            convert_vec_replicated_shares(input3.to_vec()),
        ];

        let seed = thread_rng().gen_range(0..u128::MAX);

        let (p1, p2, p3) = make_three();
        let p = [p1, p2, p3];

        let shuffled_shares = shuffling_protocol(&p, seed, &shares);

        let mut values = Fp31::from(0_u128);
        for (x, y, z) in izip!(
            &shuffled_shares[0],
            &shuffled_shares[1],
            &shuffled_shares[2]
        ) {
            values += x.0 + y.0 + z.0;
        }
        assert_eq!(values, Fp31::from(21_u128));
    }
}
