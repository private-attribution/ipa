use rand::Rng;
use sha3::{Digest, Sha3_256};

pub struct BitXORShare {
    share: u32,
}

impl BitXORShare {
    #[must_use]
    pub fn generate(value: u32) -> (Self, Self, Self) {
        let mut rng = rand::thread_rng();
        let sh1 = rng.gen::<u32>();
        let sh2 = rng.gen::<u32>();
        let sh3 = value ^ sh1 ^ sh2;

        (
            Self { share: sh1 },
            Self { share: sh2 },
            Self { share: sh3 },
        )
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

    pub fn calculate_c(r1: u128, r2: u128) -> u128 {
        r1 ^ r2
    }
}

#[cfg(test)]
mod tests {
    use super::BitXORShare;
    use super::SecureCoinTossing;
    use rand::Rng;

    fn recover_from_shares(share1: u32, share2: u32, share3: u32) -> u32 {
        share1 ^ share2 ^ share3
    }

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn generate_shares_and_recover() {
        // generate a random unsigned 32bit integer as matchkey for test.
        let mut rng = rand::thread_rng();
        let integer_matchkey = rng.gen::<u32>();
        println!("integer_matchkey = {}.", integer_matchkey);

        // generate 3 party secret shares by bit XOR from the integer matchkey.
        let (sh1, sh2, sh3) = BitXORShare::generate(integer_matchkey);
        println!(
            "Shares generated: sh1 = {}, sh2 = {}, sh3 = {}.",
            sh1.share, sh2.share, sh3.share
        );

        // recover from secret shares
        let recovered_integer_matchkey = recover_from_shares(sh1.share, sh2.share, sh3.share);
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

        let c = SecureCoinTossing::calculate_c(r1, r2);
        println!("c: {:b}", c);

        assert_eq!(c, r1 ^ r2);
    }
}
