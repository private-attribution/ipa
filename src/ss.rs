use rand::Rng;

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

#[cfg(test)]
mod tests {
    use super::BitXORShare;
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
}
