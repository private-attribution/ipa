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

#[cfg(test)]
mod tests {
    use super::BitXORShare;
    use super::RejectionSampling;
    use super::SecureCoinTossing;
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
        let dimension = 8;
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
}
