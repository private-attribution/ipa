#[cfg(all(test, unit_test))]
mod test {
    use std::{iter::zip, ops::Add};

    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use typenum::{Sum, U1, U2, U3, U4, U7};

    use super::UVStore;
    use crate::{
        ff::{Fp31, PrimeField, U128Conversions},
        protocol::ipa_prf::malicious_security::{
            lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
            prover::{TwoNPlusOne, UVPolynomial, ZeroKnowledgeProof},
        },
        secret_sharing::SharedValue,
    };

    impl Default for Fp31 {
        fn default() -> Self {
            Self::ZERO
        }
    }

    // todo: deprecate
    fn compute_final_proof<F, R>(
        uv: &UVPolynomial<F, R>,
        p_0: F,
        q_0: F,
        lagrange_table: &LagrangeTable<F, Sum<R, U1>, R>,
    ) -> GenericArray<F, TwoNPlusOne<R>>
    where
        F: PrimeField,
        R: Add + Add<U1> + ArrayLength,
        <R as Add>::Output: Add<U1>,
        <<R as Add>::Output as Add<U1>>::Output: ArrayLength,
        <R as Add<U1>>::Output: ArrayLength,
    {
        let mut p = GenericArray::<F, Sum<R, U1>>::generate(|_| F::ZERO);
        let mut q = GenericArray::<F, Sum<R, U1>>::generate(|_| F::ZERO);
        let mut proof: GenericArray<F, TwoNPlusOne<R>> = GenericArray::generate(|_| F::ZERO);
        p[0] = p_0;
        q[0] = q_0;
        proof[0] = p_0 * q_0;

        for i in 0..R::USIZE {
            p[i + 1] = uv.0[i];
            q[i + 1] = uv.1[i];
            proof[i + 1] += uv.0[i] * uv.1[i];
        }
        // We need a table of size `λ + 1` since we add a random point at x=0
        let p_extrapolated = lagrange_table.eval(&p);
        let q_extrapolated = lagrange_table.eval(&q);

        for (i, (x, y)) in zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate() {
            proof[R::USIZE + 1 + i] += x * y;
        }

        proof
    }

    impl<F, R> PartialEq<(&[u128], &[u128])> for UVStore<F, R>
    where
        F: PrimeField + std::cmp::PartialEq<u128>,
        R: ArrayLength,
    {
        fn eq(&self, other: &(&[u128], &[u128])) -> bool {
            for (i, uv_polynomial) in self.uv.iter().enumerate() {
                for (j, u) in uv_polynomial.0.iter().enumerate() {
                    if !u.eq(&other.0[i * R::USIZE + j]) {
                        return false;
                    }
                }
                for (j, v) in uv_polynomial.1.iter().enumerate() {
                    if !v.eq(&other.1[i * R::USIZE + j]) {
                        return false;
                    }
                }
            }
            true
        }
    }

    #[test]
    fn length_empty_iter() {
        let uv = (
            GenericArray::<Fp31, U2>::from_array([Fp31::ZERO; 2]),
            GenericArray::<Fp31, U2>::from_array([Fp31::ZERO; 2]),
        );

        let store = UVStore { uv: vec![uv; 1] };

        assert!(!store.is_empty());

        assert_eq!(store.len(), 2usize);

        assert_eq!(*(store.iter().next().unwrap()).0, [Fp31::ZERO; 2]);
    }

    #[test]
    fn sample_proof() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];
        const V_1: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const PROOF_1: [u128; 7] = [0, 30, 29, 30, 5, 28, 13];
        const PROOF_LEFT_1: [u128; 7] = [0, 11, 24, 8, 0, 4, 3];
        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];

        const PROOF_2: [u128; 7] = [12, 6, 15, 8, 29, 30, 6];
        const PROOF_LEFT_2: [u128; 7] = [5, 26, 14, 9, 0, 25, 2];
        const U_3: [u128; 2] = [3, 3];
        const V_3: [u128; 2] = [5, 24];

        const PROOF_3: [u128; 5] = [12, 15, 10, 14, 17];
        const P_RANDOM_WEIGHT: u128 = 12;
        const Q_RANDOM_WEIGHT: u128 = 1;

        let denominator = CanonicalLagrangeDenominator::<Fp31, U4>::new();
        let lagrange_table = LagrangeTable::<Fp31, U4, U3>::from(denominator);

        // convert to field
        let vec_u_1 = U_1
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_1 = V_1
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_u_2 = U_2
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_2 = V_2
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();

        // uv values in input format
        let uv_1 = (0usize..8)
            .map(|i| {
                (
                    *GenericArray::<Fp31, U4>::from_slice(&vec_u_1[4 * i..4 * i + 4]),
                    *GenericArray::<Fp31, U4>::from_slice(&vec_v_1[4 * i..4 * i + 4]),
                )
            })
            .collect::<Vec<_>>();
        let uv_2 = (0usize..2)
            .map(|i| {
                (
                    *GenericArray::<Fp31, U4>::from_slice(&vec_u_2[4 * i..4 * i + 4]),
                    *GenericArray::<Fp31, U4>::from_slice(&vec_v_2[4 * i..4 * i + 4]),
                )
            })
            .collect::<Vec<_>>();

        // first iteration
        let proof_1 = ZeroKnowledgeProof::<Fp31, U4>::compute_proof(uv_1.iter(), &lagrange_table);

        assert_eq!(
            proof_1.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_1,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_1 =
            GenericArray::<Fp31, U7>::generate(|i| Fp31::try_from(PROOF_LEFT_1[i]).unwrap());
        let proof_right_1 = GenericArray::<Fp31, U7>::generate(|i| proof_1.g[i] - proof_left_1[i]);

        // fiat-shamir
        let pg_2 = UVStore::<Fp31, U4>::gen_challenge_and_recurse(
            &ZeroKnowledgeProof { g: proof_left_1 },
            &ZeroKnowledgeProof { g: proof_right_1 },
            uv_1.iter(),
        );

        assert_eq!(pg_2, (&U_2[..], &V_2[..]));

        // next iteration
        let proof_2 = ZeroKnowledgeProof::<Fp31, U4>::compute_proof(uv_2.iter(), &lagrange_table);
        assert_eq!(
            proof_2.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_2,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_2 =
            GenericArray::<Fp31, U7>::generate(|i| Fp31::try_from(PROOF_LEFT_2[i]).unwrap());
        let proof_right_2 = GenericArray::<Fp31, U7>::generate(|i| proof_2.g[i] - proof_left_2[i]);

        // fiat-shamir
        let pg_3 = UVStore::<Fp31, U4>::gen_challenge_and_recurse(
            &ZeroKnowledgeProof { g: proof_left_2 },
            &ZeroKnowledgeProof { g: proof_right_2 },
            pg_2.uv.iter(),
        );

        // final proof trim pg_3 from U4 to U2
        let uv = (
            *GenericArray::<Fp31, U2>::from_slice(&pg_3.uv[0].0.as_slice()[0..2]),
            *GenericArray::<Fp31, U2>::from_slice(&pg_3.uv[0].1.as_slice()[0..2]),
        );

        assert_eq!(UVStore { uv: vec![uv; 1] }, (&U_3[..], &V_3[..]));

        // final iteration
        let denominator = CanonicalLagrangeDenominator::<Fp31, U3>::new();
        let lagrange_table = LagrangeTable::<Fp31, U3, U2>::from(denominator);
        let proof_3 = compute_final_proof::<Fp31, U2>(
            &uv,
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
            &lagrange_table,
        );
        assert_eq!(
            proof_3.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_3,
        );
    }
}
