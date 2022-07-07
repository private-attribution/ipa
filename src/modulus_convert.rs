pub mod modulus_conversion {

    use rand::Rng;
    use rand::RngCore;

    pub struct ReplicatedBinarySecretSharing {
        pub sh1: u8,
        pub sh2: u8,
    }

    pub struct ReplicatedSecretSharing {
        pub sh1: u64,
        pub sh2: u64,
    }

    pub fn gen_r_binary_sharings<R: RngCore>(
        mut rng_1: R,
        mut rng_2: R,
        batch_size: usize,
    ) -> Vec<ReplicatedBinarySecretSharing> {
        let mut output_shares = Vec::with_capacity(batch_size);
        for _i in 0..(batch_size - 1) {
            output_shares.push(ReplicatedBinarySecretSharing {
                sh1: rng_1.gen_range(0..2),
                sh2: rng_2.gen_range(0..2),
            });
        }
        output_shares
    }

    pub fn mult_r1_r2_helper1<R: RngCore>(
        mut rng_3_1: R,
        r_binary_shares: &[ReplicatedBinarySecretSharing],
        p: u64,
        batch_size: usize,
    ) -> (Vec<ReplicatedSecretSharing>, Vec<u64>) {
        let mut output_shares = Vec::with_capacity(batch_size);
        let mut values_to_share = Vec::with_capacity(batch_size);
        for shares in r_binary_shares {
            let r1 = shares.sh1;
            let r2 = shares.sh2;
            let s_3_1: u64 = rng_3_1.gen_range(0..p);
            // (r1 * r2 - s_3_1) mod p
            let d: u64 = sub_mod_p(u64::from(r1 * r2), s_3_1, p);
            output_shares.push(ReplicatedSecretSharing { sh1: s_3_1, sh2: d });
            values_to_share.push(d);
        }
        (output_shares, values_to_share)
    }

    #[must_use]
    pub fn mult_r1_r2_helper2(d_values: &[u64]) -> Vec<ReplicatedSecretSharing> {
        d_values
            .iter()
            .map(|&d| ReplicatedSecretSharing { sh1: d, sh2: 0 })
            .collect()
    }

    pub fn mult_r1_r2_helper3<R: RngCore>(
        mut rng_3_1: R,
        p: u64,
        batch_size: usize,
    ) -> Vec<ReplicatedSecretSharing> {
        let mut output_shares = Vec::with_capacity(batch_size);
        for _i in 0..(batch_size - 1) {
            let s_3_1 = rng_3_1.gen_range(0..p);
            output_shares.push(ReplicatedSecretSharing { sh1: 0, sh2: s_3_1 });
        }
        output_shares
    }

    pub fn xor_r1_r2_r3_helper1<R: RngCore>(
        mut rng_1_2: R,
        r_binary_shares: &[ReplicatedBinarySecretSharing],
        shares_of_r1r2: &[ReplicatedSecretSharing],
        received_values: &[u64],
        p: u64,
        batch_size: usize,
    ) -> Vec<ReplicatedSecretSharing> {
        let mut output_shares = Vec::with_capacity(batch_size);
        for i in 0..(batch_size - 1) {
            let alpha_1 = sub_mod_p(
                u64::from(r_binary_shares[i].sh1),
                mult_mod_p(2, shares_of_r1r2[i].sh1, p),
                p,
            );
            let alpha_2 = sub_mod_p(
                u64::from(r_binary_shares[i].sh2),
                mult_mod_p(2, shares_of_r1r2[i].sh2, p),
                p,
            );
            let s_1_2: u64 = rng_1_2.gen_range(0..p);

            output_shares.push(ReplicatedSecretSharing {
                sh1: sub_mod_p(alpha_1, mult_mod_p(2, received_values[i], p), p),
                sh2: sub_mod_p(alpha_2, mult_mod_p(2, s_1_2, p), p),
            });
        }
        output_shares
    }

    pub fn xor_r1_r2_r3_helper2<R: RngCore>(
        mut rng_1_2: R,
        mut rng_2_3: R,
        r_binary_shares: &[ReplicatedBinarySecretSharing],
        shares_of_r1r2: &[ReplicatedSecretSharing],
        p: u64,
        batch_size: usize,
    ) -> (Vec<ReplicatedSecretSharing>, Vec<u64>) {
        // To send to helper 3
        let mut values_to_share = Vec::with_capacity(batch_size);
        let mut output_shares = Vec::with_capacity(batch_size);
        for i in 0..(batch_size - 1) {
            let alpha_2: u64 = sub_mod_p(
                u64::from(r_binary_shares[i].sh1),
                mult_mod_p(2, shares_of_r1r2[i].sh1, p),
                p,
            );
            let s_1_2: u64 = rng_1_2.gen_range(0..p);
            let s_2_3: u64 = rng_2_3.gen_range(0..p);
            let d_2: u64 = sub_mod_p(alpha_2 * u64::from(r_binary_shares[i].sh2), s_1_2, p);
            output_shares.push(ReplicatedSecretSharing {
                sh1: sub_mod_p(alpha_2, mult_mod_p(2, s_1_2, p), p),
                sh2: sub_mod_p(
                    u64::from(r_binary_shares[i].sh2),
                    mult_mod_p(2, add_mod_p(d_2, s_2_3, p), p),
                    p,
                ),
            });
            values_to_share.push(d_2);
        }
        (output_shares, values_to_share)
    }

    pub fn xor_r1_r2_r3_helper3<R: RngCore>(
        mut rng_2_3: R,
        r_binary_shares: &[ReplicatedBinarySecretSharing],
        shares_of_r1r2: &[ReplicatedSecretSharing],
        d2_values: &[u64],
        p: u64,
        batch_size: usize,
    ) -> (Vec<ReplicatedSecretSharing>, Vec<u64>) {
        // To send to helper 1
        let mut d3_values = Vec::with_capacity(batch_size);
        let mut output_shares = Vec::with_capacity(batch_size);
        for i in 0..(batch_size - 1) {
            let alpha_1 = sub_mod_p(
                u64::from(r_binary_shares[i].sh2),
                mult_mod_p(2, shares_of_r1r2[i].sh2, p),
                p,
            );
            let s_2_3: u64 = rng_2_3.gen_range(0..p);
            let r3: u64 = u64::from(r_binary_shares[i].sh1);
            let d_3 = sub_mod_p(alpha_1 * r3, s_2_3, p);
            d3_values.push(d_3);
            output_shares.push(ReplicatedSecretSharing {
                sh1: sub_mod_p(r3, mult_mod_p(2, add_mod_p(d2_values[i], s_2_3, p), p), p),
                sh2: sub_mod_p(alpha_1, mult_mod_p(2, d_3, p), p),
            });
        }
        (output_shares, d3_values)
    }

    // a and b should both be less than p
    #[must_use]
    pub fn add_mod_p(a: u64, b: u64, p: u64) -> u64 {
        let offset: u64 = u64::MAX - p + 1;

        let (sum, overlow) = a.overflowing_add(b);
        if overlow {
            return sum + offset;
        } else if sum >= p {
            return sum - p;
        }
        sum
    }

    // a and b should both be less than p
    #[must_use]
    pub fn sub_mod_p(a: u64, b: u64, p: u64) -> u64 {
        let offset: u64 = u64::MAX - p + 1;

        let (difference, overlow) = a.overflowing_sub(b);
        if overlow {
            return difference - offset;
        }
        difference
    }

    // a and b should both be less than p
    #[must_use]
    pub fn mult_mod_p(a: u64, b: u64, p: u64) -> u64 {
        let (a, b, p) = (u128::from(a), u128::from(b), u128::from(p));

        // There will not be any trunction, because "mod p" returns
        // a value less than p, and p is less than u64
        #[allow(clippy::cast_possible_truncation)]
        (((a * b) % p) as u64)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::modulus_convert::modulus_conversion::add_mod_p;
    use crate::modulus_convert::modulus_conversion::gen_r_binary_sharings;
    use crate::modulus_convert::modulus_conversion::mult_mod_p;

    use crate::modulus_convert::modulus_conversion::mult_r1_r2_helper1;
    use crate::modulus_convert::modulus_conversion::mult_r1_r2_helper2;
    use crate::modulus_convert::modulus_conversion::mult_r1_r2_helper3;

    use crate::modulus_convert::modulus_conversion::xor_r1_r2_r3_helper1;
    use crate::modulus_convert::modulus_conversion::xor_r1_r2_r3_helper2;
    use crate::modulus_convert::modulus_conversion::xor_r1_r2_r3_helper3;

    use crate::modulus_convert::modulus_conversion::sub_mod_p;

    #[test]
    fn test_add_mod_p() {
        assert_eq!(add_mod_p(1u64, 1u64, 31u64), 2u64);

        assert_eq!(add_mod_p(0u64, 0u64, 31u64), 0u64);

        assert_eq!(add_mod_p(6u64, 24u64, 31u64), 30u64);

        assert_eq!(add_mod_p(7u64, 24u64, 31u64), 0u64);

        assert_eq!(add_mod_p(8u64, 24u64, 31u64), 1u64);

        assert_eq!(add_mod_p(30u64, 30u64, 31u64), 29u64);

        assert_eq!(add_mod_p(0u64, 0u64, 18_446_744_073_709_551_557_u64), 0u64);

        assert_eq!(add_mod_p(1u64, 1u64, 18_446_744_073_709_551_557_u64), 2u64);

        assert_eq!(
            add_mod_p(200u64, 700u64, 18_446_744_073_709_551_557_u64),
            900u64
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                0u64,
                18_446_744_073_709_551_557_u64
            ),
            18_446_744_073_709_551_556_u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                1u64,
                18_446_744_073_709_551_557_u64
            ),
            0u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                6u64,
                18_446_744_073_709_551_557_u64
            ),
            5u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                1_000_001_u64,
                18_446_744_073_709_551_557_u64
            ),
            1_000_000_u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                18_446_744_073_709_551_556_u64,
                18_446_744_073_709_551_557_u64
            ),
            18_446_744_073_709_551_555_u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                59u64,
                18_446_744_073_709_551_557_u64
            ),
            58u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                60u64,
                18_446_744_073_709_551_557_u64
            ),
            59u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                61u64,
                18_446_744_073_709_551_557_u64
            ),
            60u64,
        );

        assert_eq!(
            add_mod_p(
                18_446_744_073_709_551_556_u64,
                59u64,
                18_446_744_073_709_551_557_u64
            ),
            58u64,
        );
    }

    #[test]
    fn test_sub_mod_p() {
        assert_eq!(sub_mod_p(0u64, 0u64, 31u64), 0u64);
        assert_eq!(sub_mod_p(1u64, 1u64, 31u64), 0u64);
        assert_eq!(sub_mod_p(30u64, 1u64, 31u64), 29u64);

        assert_eq!(sub_mod_p(0u64, 1u64, 31u64), 30u64);
        assert_eq!(sub_mod_p(0u64, 11u64, 31u64), 20u64);
        assert_eq!(sub_mod_p(10u64, 11u64, 31u64), 30u64);
        assert_eq!(sub_mod_p(5u64, 28u64, 31u64), 8u64);

        assert_eq!(sub_mod_p(10u64, 1u64, 18_446_744_073_709_551_557_u64), 9u64,);

        assert_eq!(
            sub_mod_p(0u64, 1u64, 18_446_744_073_709_551_557_u64),
            18_446_744_073_709_551_556_u64,
        );

        assert_eq!(
            sub_mod_p(0u64, 59u64, 18_446_744_073_709_551_557_u64),
            18_446_744_073_709_551_498_u64,
        );

        assert_eq!(
            sub_mod_p(0u64, 60u64, 18_446_744_073_709_551_557_u64),
            18_446_744_073_709_551_497_u64,
        );

        assert_eq!(
            sub_mod_p(0u64, 61u64, 18_446_744_073_709_551_557_u64),
            18_446_744_073_709_551_496_u64,
        );
    }

    #[test]
    fn test_mult_mod_p() {
        assert_eq!(mult_mod_p(0u64, 0u64, 31u64), 0u64);
        assert_eq!(mult_mod_p(1u64, 1u64, 31u64), 1u64);
        assert_eq!(mult_mod_p(3u64, 7u64, 31u64), 21u64);
        assert_eq!(mult_mod_p(5u64, 7u64, 31u64), 4u64);
        assert_eq!(mult_mod_p(30u64, 7u64, 31u64), 24u64);
        assert_eq!(mult_mod_p(30u64, 30u64, 31u64), 1u64);

        assert_eq!(mult_mod_p(0u64, 0u64, 18_446_744_073_709_551_557_u64), 0u64,);
        assert_eq!(mult_mod_p(0u64, 1u64, 18_446_744_073_709_551_557_u64), 0u64,);
        assert_eq!(mult_mod_p(1u64, 1u64, 18_446_744_073_709_551_557_u64), 1u64,);
        assert_eq!(
            mult_mod_p(53u64, 9u64, 18_446_744_073_709_551_557_u64),
            477u64,
        );

        assert_eq!(
            mult_mod_p(
                4_294_967_295_u64,
                4_294_967_296_u64,
                18_446_744_073_709_551_557_u64
            ),
            18_446_744_069_414_584_320_u64,
        );
        assert_eq!(
            mult_mod_p(
                4_294_967_296_u64,
                4_294_967_296_u64,
                18_446_744_073_709_551_557_u64
            ),
            59u64,
        );
        assert_eq!(
            mult_mod_p(
                2u64,
                9_223_372_036_854_775_804_u64,
                18_446_744_073_709_551_557_u64
            ),
            51u64,
        );
        assert_eq!(
            mult_mod_p(
                10_000_000_000_000_000_000_u64,
                10_000_000_000_000_000_000_u64,
                18_446_744_073_709_551_557_u64
            ),
            6_932_391_181_562_104_841_u64,
        );
        assert_eq!(
            mult_mod_p(
                14_140_769_320_479_119_572_u64,
                16_523_972_853_534_698_712_u64,
                18_446_744_073_709_551_557_u64
            ),
            1_263_076_288_923_396_945_u64,
        );
    }

    #[test]
    fn test_three_helpers() {
        // let p = 2147483647; // 2^31 - 1
        // let p = 2305843009213693951; // 2^61 - 1
        let p = 18_446_744_073_709_551_557; // 2^64 - 59
        let batch_size = 100;

        // Helper 1 and 3 will share this seed
        let seed_1: [u8; 32] = [1; 32];

        // Helper 2 and 1 will share this seed
        let seed_2: [u8; 32] = [2; 32];

        // Helper 3 and 2 will share this seed
        let seed_3: [u8; 32] = [3; 32];

        // Helper 1
        let mut helper1_rng_1 = StdRng::from_seed(seed_1);
        let mut helper1_rng_2 = StdRng::from_seed(seed_2);
        let h1_binary_shares =
            gen_r_binary_sharings(&mut helper1_rng_1, &mut helper1_rng_2, batch_size);

        // Helper 2
        let mut helper2_rng_2 = StdRng::from_seed(seed_2);
        let mut helper2_rng_3 = StdRng::from_seed(seed_3);
        let h2_binary_shares =
            gen_r_binary_sharings(&mut helper2_rng_2, &mut helper2_rng_3, batch_size);

        // Helper 3
        let mut helper3_rng_3 = StdRng::from_seed(seed_3);
        let mut helper3_rng_1 = StdRng::from_seed(seed_1);
        let h3_binary_shares =
            gen_r_binary_sharings(&mut helper3_rng_3, &mut helper3_rng_1, batch_size);

        for i in 0..batch_size - 1 {
            assert_eq!(h1_binary_shares[i].sh1, h3_binary_shares[i].sh2);
            assert_eq!(h2_binary_shares[i].sh1, h1_binary_shares[i].sh2);
            assert_eq!(h3_binary_shares[i].sh1, h2_binary_shares[i].sh2);
        }

        // Multiply r1 * r2
        // Helper 1 generates random values (s) and uses them to mask r1*r2 in the values (d)
        let (h1_shares_of_r1r2, h1_d_values) =
            mult_r1_r2_helper1(&mut helper1_rng_1, &h1_binary_shares, p, batch_size);

        // Helper 3 generates the same random values (s) from their shared randomness
        let h3_shares_of_r1r2 = mult_r1_r2_helper3(&mut helper3_rng_1, p, batch_size);

        // Helper 1 sends the d_values to Helper 2
        let h2_shares_of_r1r2 = mult_r1_r2_helper2(&h1_d_values);

        for i in 0..batch_size - 1 {
            // Check that this is a valid replicated secret sharing
            assert_eq!(h1_shares_of_r1r2[i].sh1, h3_shares_of_r1r2[i].sh2);
            assert_eq!(h2_shares_of_r1r2[i].sh1, h1_shares_of_r1r2[i].sh2);
            assert_eq!(h3_shares_of_r1r2[i].sh1, h2_shares_of_r1r2[i].sh2);

            // Check that this is indeed a secret sharing of r1*r2
            let r1_r2 = h1_binary_shares[i].sh1 * h1_binary_shares[i].sh2;

            let sanity_check_1 = add_mod_p(
                add_mod_p(h1_shares_of_r1r2[i].sh1, h2_shares_of_r1r2[i].sh1, p),
                h3_shares_of_r1r2[i].sh1,
                p,
            );
            let sanity_check_2 = add_mod_p(
                add_mod_p(h1_shares_of_r1r2[i].sh2, h2_shares_of_r1r2[i].sh2, p),
                h3_shares_of_r1r2[i].sh2,
                p,
            );
            assert_eq!(u64::from(r1_r2), sanity_check_1);
            assert_eq!(u64::from(r1_r2), sanity_check_2);
        }

        // Locally compute (r1 ^ r2)
        // Compute (r1 ^ r2) * r3
        // Then locally compute (r1 ^ r2) ^ r3

        // Helper 2 generates "d2" values and local shares of (r1 ^ r2) ^ r3
        let (h2_shares, d2_values) = xor_r1_r2_r3_helper2(
            helper2_rng_2,
            helper2_rng_3,
            &h2_binary_shares,
            &h2_shares_of_r1r2,
            p,
            batch_size,
        );

        // Helper 2 sends the "d2" values to Helper 3

        // Helper 3 generates "d3" values and local shares of (r1 ^ r2) ^ r3
        let (h3_shares, d3_values) = xor_r1_r2_r3_helper3(
            helper3_rng_3,
            &h3_binary_shares,
            &h3_shares_of_r1r2,
            &d2_values,
            p,
            batch_size,
        );

        // Helper 3 sends the "d3" values to Helper 1

        // Helper 1 generates local shares of (r1 ^ r2) ^ r3
        let h1_shares = xor_r1_r2_r3_helper1(
            helper1_rng_2,
            &h1_binary_shares,
            &h1_shares_of_r1r2,
            &d3_values,
            p,
            batch_size,
        );

        for i in 0..batch_size - 1 {
            // Check that we have a replicated secret sharing
            assert_eq!(h1_shares[i].sh1, h3_shares[i].sh2);
            assert_eq!(h2_shares[i].sh1, h1_shares[i].sh2);
            assert_eq!(h3_shares[i].sh1, h2_shares[i].sh2);

            // Check that this is a secret sharing of (r1 ^ r2) ^ r3
            let res = add_mod_p(
                add_mod_p(h1_shares[i].sh1, h2_shares[i].sh1, p),
                h3_shares[i].sh1,
                p,
            );
            let correct =
                (h1_binary_shares[i].sh1 + h2_binary_shares[i].sh1 + h3_binary_shares[i].sh1) % 2;
            assert_eq!(res, u64::from(correct));
        }
    }
}
