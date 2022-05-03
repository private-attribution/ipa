use rand::Rng;
use sha3::{Digest, Sha3_256};

pub struct BitXORShare {}

impl BitXORShare {
    #[must_use]
    pub fn create(value: u32, share_amount: u8) -> Vec<u32> {
        if share_amount < 2 {
            panic!("Amount of shares must be at least 2.");
        }
        let mut rng = rand::thread_rng();
        let mut last_sh = value;
        let mut sh_vec = vec![];
        for _i in 0..share_amount - 1 {
            let sh = rng.gen::<u32>();
            sh_vec.push(sh);
            last_sh ^= sh;
        }
        sh_vec.push(last_sh);
        sh_vec
    }

    pub fn combine(shares: Vec<u32>) -> u32 {
        let mut value = 0;
        for sh in shares {
            if value == 0 {
                value = sh;
            } else {
                value ^= sh;
            }
        }
        value
    }
}

pub struct SecureCoinTossing {}

impl SecureCoinTossing {
    pub fn get_random_and_hash() -> (u128, String) {
        // generate a u128 random integer.
        let mut rng = rand::thread_rng();
        let r = rng.gen::<u128>();

        // generate hash for the random integer's bit string.
        let mut hasher = Sha3_256::new();
        hasher.update(format!("{:b}", r));
        let h: String = format!("{:X}", hasher.finalize());
        (r, h)
    }

    pub fn get_random() -> u128 {
        // generate a u128 random integer.
        let mut rng = rand::thread_rng();
        rng.gen::<u128>()
    }

    pub fn verify_random_and_hash(r: u128, h: String) -> bool {
        // generate hash for the random integer's bit string.
        let mut hasher = Sha3_256::new();
        hasher.update(format!("{:b}", r));
        let hv: String = format!("{:X}", hasher.finalize());
        h == hv
    }

    pub fn calculate_shared_random(r1: u128, r2: u128) -> u128 {
        r1 ^ r2
    }
}

pub struct RejectionSampling {}

impl RejectionSampling {
    pub fn generate_permutation(bit_string_as_int: u128, dimension: usize) -> Vec<usize> {
        // Check if input dimension can be supported.
        // bit_string_as_int is 128 bit. It only enough to generate 4 bit dimension.
        // E.g. if demension is 30, we needs 5 bits to generate 1 integer number
        // between 1 to 30, and we need at least 30 group of 5 bits to generate
        // 20 number to meet the demension. 5 bits times 30 is bigger 128 bit.
        let max_dimension = 2usize.pow(4);
        if dimension > max_dimension {
            panic!(
                "dimension ({}) > {} is not supported!",
                dimension, max_dimension
            );
        }

        // calculate how many bit we need to generate an integer number in dimension.
        // ceiling of log2(n), n is the number of dimensions.
        let bit = ((dimension) as f64).log2().ceil() as u8;

        // covert bit_string_as_int to bit_string.
        let bit_string = format!("{:b}", bit_string_as_int);

        let mut v = vec![];
        let mut i = 0;
        while (bit * (i + i) < 128) & (v.len() < dimension as usize) {
            let intval =
                usize::from_str_radix(&bit_string[(bit * i) as usize..(bit * (i + 1)) as usize], 2)
                    .unwrap();
            if (intval < dimension) & !v.contains(&(intval)) {
                v.push(intval);
            }
            i += 1;
        }
        v
    }
}

pub struct ThreePartyHideAndSeek {}

impl ThreePartyHideAndSeek {
    fn hider_local_permutation(
        original_shares: [u32; BATCH_SIZE],
        shared_random: u128,
    ) -> [u32; BATCH_SIZE] {
        let permutation = RejectionSampling::generate_permutation(shared_random, BATCH_SIZE);
        let mut permuted_shares = [0; BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            permuted_shares[i] = original_shares[permutation[i]];
        }
        permuted_shares
    }

    pub fn shuffle(seeker: &mut Helper, hider1: &mut Helper, hider2: &mut Helper) {
        // Seeker node send it's share to Hider1 node.
        // TODO: distrubite in network.
        let seeker_sh = seeker.share; // [Assume] Hider1 has a copy of Seeker's sahre.

        // Hider1: Combin seeker and hider1 shares
        let mut combined_sh = [0; BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            combined_sh[i] = BitXORShare::combine(vec![seeker_sh[i], hider1.share[i]]);
        }
        // Hider1: Generate random nubmer and its hash for Secure Coin Tossing.
        let (r1, h1) = SecureCoinTossing::get_random_and_hash();
        // Hider1 send the hash to Hider2.
        let copy_of_h1 = h1; // [Assume] Hider2 has a copy of r1's hash.

        // Hider2: Generate random number for Secure Coin Tossing.
        let r2 = SecureCoinTossing::get_random();
        // Hider2: send own random number to another hider.
        let copy_of_r2 = r2; // [Assume] Hider1 has a copy of r2.

        // Hider1: send own random number to another hider.
        let copy_of_r1 = r1; // [Assume] Hider2 has a copy of r1.

        // Hider2: verify if r1 is match the hash.
        if !SecureCoinTossing::verify_random_and_hash(copy_of_r1, copy_of_h1) {
            panic!("The random number isn't match the hash.")
        };

        // Hider1: calculate shared random number and permute combined share by Rejection Sampling.
        let permuted_combined_sh = Self::hider_local_permutation(
            combined_sh,
            SecureCoinTossing::calculate_shared_random(r1, copy_of_r2),
        );
        // Hider1: create new shares for Seeker and Hider1.
        let mut permuted_seeker_sh = [0; BATCH_SIZE];
        let mut permuted_hider1_sh = [0; BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            let shares = BitXORShare::create(permuted_combined_sh[i], 2);
            permuted_seeker_sh[i] = shares[0];
            permuted_hider1_sh[i] = shares[1];
        }
        seeker.share = permuted_seeker_sh;
        hider1.share = permuted_hider1_sh;

        //Hider2: calculate shared random number and permute combined share by Rejection Sampling.
        let permuted_hider2_sh = Self::hider_local_permutation(
            hider2.share,
            SecureCoinTossing::calculate_shared_random(copy_of_r1, r2),
        );
        hider2.share = permuted_hider2_sh;
    }
}

pub const BATCH_SIZE: usize = 4;

pub struct Helper {
    pub share: [u32; BATCH_SIZE], // TODO: extend to support multiple values, such as matchkey, source/trigger flag, trigger  value.
}

#[cfg(test)]
mod tests {
    use super::BitXORShare;
    use super::Helper;
    use super::RejectionSampling;
    use super::SecureCoinTossing;
    use super::ThreePartyHideAndSeek;
    use super::BATCH_SIZE;
    use rand::Rng;

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn generate_shares_and_recover() {
        // generate a random unsigned 32bit integer as matchkey for test.
        let mut rng = rand::thread_rng();
        let integer_matchkey = rng.gen::<u32>();
        println!("integer_matchkey = {}.", integer_matchkey);

        // generate 3 party secret shares by bit XOR from the integer matchkey.
        let shares = BitXORShare::create(integer_matchkey, 255);
        println!("{}", shares.len());
        print!("Shares generated:");
        for i in 0..(shares.len() - 1) {
            print!(" sh{}={},", i, shares[i + 1]);
        }
        println!(" sh{}={}.", shares.len(), shares[shares.len() - 1]);

        // recover from secret shares
        let recovered_integer_matchkey = BitXORShare::combine(shares);
        println!(
            "recovered_integer_matchkey = {}.",
            recovered_integer_matchkey
        );

        assert_eq!(integer_matchkey, recovered_integer_matchkey);
    }

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn test_generate_random_u128_and_hash() {
        let (r1, h1) = SecureCoinTossing::get_random_and_hash();
        println!("r1: {:b}", r1);
        println!("h1: {}", h1);

        let r2 = SecureCoinTossing::get_random();
        println!("r2: {:b}", r2);

        assert_eq!(
            SecureCoinTossing::verify_random_and_hash(r1, h1.clone()),
            true
        );
        assert_eq!(SecureCoinTossing::verify_random_and_hash(r2, h1), false);

        let c = SecureCoinTossing::calculate_shared_random(r1, r2);
        println!("c: {:b}", c);

        assert_eq!(c, r1 ^ r2);
    }

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn test_generate_permutation() {
        let dimension = BATCH_SIZE;
        let r1 = SecureCoinTossing::get_random();
        let mut v = RejectionSampling::generate_permutation(r1, dimension);
        println!("{:?}", v);
        print!("{} numbers generated.", v.len());
        if v.len() < dimension as usize {
            print!(" No enought bits to generate {} numbers.", dimension);
        }
        println!();

        for i in &v {
            assert_eq!(i >= &0, true);
            assert_eq!(i < &dimension, true);
        }
        v.sort();
        v.dedup();
        assert_eq!(v.len(), (dimension as usize));
    }

    fn combine_shares_and_aggregate(
        sh1: [u32; BATCH_SIZE],
        sh2: [u32; BATCH_SIZE],
        sh3: [u32; BATCH_SIZE],
    ) -> u64 {
        let mut combined_sh = [0; BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            combined_sh[i] = BitXORShare::combine(vec![sh1[i], sh2[i], sh3[i]]) as u64;
        }
        combined_sh.iter().sum()
    }

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn test_three_party_hide_and_seek_shuffling() {
        // Generate a random u32 value as the value to secret share.
        let mut rng = rand::thread_rng();
        // Create 3 party secret shares
        let mut sh1 = [0; BATCH_SIZE];
        let mut sh2 = [0; BATCH_SIZE];
        let mut sh3 = [0; BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            let value = rng.gen::<u32>();
            let shares = BitXORShare::create(value, 3);
            sh1[i] = shares[0];
            sh2[i] = shares[1];
            sh3[i] = shares[2];
        }
        // Send each share to a helper.
        // TODO: distribut helpers to network.
        let mut helper1 = Helper { share: sh1 };
        let mut helper2 = Helper { share: sh2 };
        let mut helper3 = Helper { share: sh3 };

        // Calculate aggregated value before shuffling for later comparison.
        let aggregated_value =
            combine_shares_and_aggregate(helper1.share, helper2.share, helper3.share);
        // Print original secret shared value batch and the aggregated value.
        println!("Orginal shares:");
        println!("sh1: {:?}", helper1.share);
        println!("sh2: {:?}", helper2.share);
        println!("sh3: {:?}", helper3.share);
        println!("Orginal share aggregated value: {}", aggregated_value);

        // Shuffle with each helper as "Seeker" a time.
        ThreePartyHideAndSeek::shuffle(&mut helper1, &mut helper2, &mut helper3);
        ThreePartyHideAndSeek::shuffle(&mut helper2, &mut helper3, &mut helper1);
        ThreePartyHideAndSeek::shuffle(&mut helper3, &mut helper1, &mut helper2);

        // Calculate aggregated value after shuffle
        let post_shuffling_aggregated_value =
            combine_shares_and_aggregate(helper1.share, helper2.share, helper3.share);

        // Print post shuffling secret shared value batch and the aggregated value.
        println!("Post shuffling:");
        println!("sh1: {:?}", helper1.share);
        println!("sh2: {:?}", helper2.share);
        println!("sh3: {:?}", helper3.share);
        println!(
            "Post shuffling aggregated value: {}",
            post_shuffling_aggregated_value
        );

        assert_eq!(aggregated_value, post_shuffling_aggregated_value);
    }
}
