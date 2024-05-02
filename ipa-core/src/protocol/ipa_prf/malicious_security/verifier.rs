use std::ops::{Add, Sub};

use generic_array::ArrayLength;
use typenum::{Sum, U1};

use super::prover::{TwoNMinusOne, TwoNPlusOne, ZeroKnowledgeProof};
use crate::{
    ff::PrimeField,
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

pub struct ProofVerifier<F: PrimeField> {
    u_or_v: Vec<F>,
    out_share: F,
}

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
///
#[allow(non_camel_case_types)]
impl<F> ProofVerifier<F>
where
    F: PrimeField,
{
    pub fn new(u_or_v: Vec<F>, out_share: F) -> Self {
        Self { u_or_v, out_share }
    }

    pub fn verify_proof<λ>(
        &self,
        zkp: &ZeroKnowledgeProof<F, TwoNMinusOne<λ>>,
        r: F,
    ) -> (F, ProofVerifier<F>)
    where
        λ: ArrayLength + Add + Sub<U1>,
        <λ as Add>::Output: Sub<U1>,
        <<λ as Add>::Output as Sub<U1>>::Output: ArrayLength,
        <λ as Sub<U1>>::Output: ArrayLength,
    {
        debug_assert_eq!(self.u_or_v.len() % λ::USIZE, 0); // We should pad with zeroes eventually

        let s = self.u_or_v.len() / λ::USIZE;

        assert!(
            s > 1,
            "When the output is this small, you should call `verify_final_proof`"
        );

        let denominator_g = CanonicalLagrangeDenominator::<F, TwoNMinusOne<λ>>::new();
        let lagrange_table_g = LagrangeTable::<F, TwoNMinusOne<λ>, U1>::new(&denominator_g, &r);
        let g_r_share = lagrange_table_g.eval(&zkp.g)[0];
        let sum_share = (0..λ::USIZE).fold(F::ZERO, |acc, i| acc + zkp.g[i]);

        // Reveal `b_share` to one another to reconstruct `b` and check if `b = 0`. If the check doesn't pass, abort.
        let b_share = sum_share - self.out_share;

        let denominator_p_or_q = CanonicalLagrangeDenominator::<F, λ>::new();
        let lagrange_table_p_or_q_r = LagrangeTable::<F, λ, U1>::new(&denominator_p_or_q, &r);
        let p_or_q_r = (0..s)
            .map(|i| {
                let start = i * λ::USIZE;
                let end = start + λ::USIZE;
                let p_or_q = &self.u_or_v[start..end];
                lagrange_table_p_or_q_r.eval(p_or_q)[0]
            })
            .collect();
        (
            b_share,
            ProofVerifier {
                u_or_v: p_or_q_r,
                out_share: g_r_share,
            },
        )
    }

    pub fn verify_final_proof<λ>(
        &self,
        zkp: &ZeroKnowledgeProof<F, TwoNPlusOne<λ>>,
        r: F,
        p_or_q_0: F,
    ) -> (F, F)
    where
        λ: ArrayLength + Add + Add<U1>,
        <λ as Add>::Output: Add<U1>,
        <<λ as Add>::Output as Add<U1>>::Output: ArrayLength,
        <λ as Add<U1>>::Output: ArrayLength,
    {
        assert_eq!(self.u_or_v.len(), λ::USIZE); // We should pad with zeroes eventually

        // We need a table of size `λ + 1` since we add a random point at x=0
        let denominator = CanonicalLagrangeDenominator::<F, Sum<λ, U1>>::new();
        let lagrange_table = LagrangeTable::<F, Sum<λ, U1>, U1>::new(&denominator, &r);

        let mut p_or_q = vec![p_or_q_0];
        p_or_q.extend_from_slice(&self.u_or_v);
        let p_or_q_extrapolated = lagrange_table.eval(&p_or_q)[0];

        let denominator_g = CanonicalLagrangeDenominator::<F, TwoNPlusOne<λ>>::new();
        let lagrange_table_g = LagrangeTable::<F, TwoNPlusOne<λ>, U1>::new(&denominator_g, &r);
        let out_share = lagrange_table_g.eval(&zkp.g)[0];

        (p_or_q_extrapolated, out_share)
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use typenum::{U2, U4, U5, U7};

    use super::ProofVerifier;
    use crate::{
        ff::{Fp31, U128Conversions},
        protocol::ipa_prf::malicious_security::prover::ZeroKnowledgeProof,
    };

    #[test]
    fn sample_proof_u() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];
        const OUT_1: u128 = 27;
        const ZKP_1: [u128; 7] = [0, 0, 13, 17, 11, 25, 7];
        const R_1: u128 = 22;

        const EXPECTED_G_R_1: u128 = 0;
        const EXPECTED_B_1: u128 = 3;

        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const ZKP_2: [u128; 7] = [11, 25, 17, 9, 22, 23, 3];
        const R_2: u128 = 17;

        const EXPECTED_G_R_2: u128 = 13;
        const EXPECTED_B_2: u128 = 0;

        const ZKP_3: [u128; 5] = [21, 1, 6, 25, 1];
        const U_3: [u128; 2] = [3, 3];
        const R_3: u128 = 30;
        const P_RANDOM_WEIGHT: u128 = 12;

        const EXPECTED_P_FINAL: u128 = 30;
        const EXPECTED_G_R_FINAL: u128 = 0;

        let pv_1: ProofVerifier<Fp31> = ProofVerifier::new(
            U_1.into_iter()
                .map(|x| Fp31::try_from(x).unwrap())
                .collect(),
            Fp31::try_from(OUT_1).unwrap(),
        );

        // first iteration
        let zkp_1 = ZeroKnowledgeProof::<Fp31, U7>::new(ZKP_1.map(|x| Fp31::try_from(x).unwrap()));

        let (b_share_1, pv_2) = pv_1.verify_proof::<U4>(&zkp_1, Fp31::try_from(R_1).unwrap());
        assert_eq!(b_share_1.as_u128(), EXPECTED_B_1);
        assert_eq!(
            pv_2.u_or_v.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            U_2,
        );
        assert_eq!(pv_2.out_share.as_u128(), EXPECTED_G_R_1);

        // second iteration
        let zkp_2 = ZeroKnowledgeProof::<Fp31, U7>::new(ZKP_2.map(|x| Fp31::try_from(x).unwrap()));

        let (b_share_2, pv_3) = pv_2.verify_proof::<U4>(&zkp_2, Fp31::try_from(R_2).unwrap());
        assert_eq!(b_share_2.as_u128(), EXPECTED_B_2);
        assert_eq!(
            pv_3.u_or_v.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            U_3,
        );
        assert_eq!(pv_3.out_share.as_u128(), EXPECTED_G_R_2);

        // final iteration
        let zkp_3 = ZeroKnowledgeProof::<Fp31, U5>::new(ZKP_3.map(|x| Fp31::try_from(x).unwrap()));

        let (p_final, out_share) = pv_3.verify_final_proof::<U2>(
            &zkp_3,
            Fp31::try_from(R_3).unwrap(),
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
        );

        assert_eq!(p_final.as_u128(), EXPECTED_P_FINAL);
        assert_eq!(out_share.as_u128(), EXPECTED_G_R_FINAL);
    }

    #[test]
    fn sample_proof_v() {
        const V_1: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const OUT_1: u128 = 0;
        const ZKP_1: [u128; 7] = [0, 30, 16, 13, 25, 3, 6];
        const R_1: u128 = 22;

        const EXPECTED_G_R_1: u128 = 10;
        const EXPECTED_B_1: u128 = 28;

        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];
        const ZKP_2: [u128; 7] = [1, 12, 29, 30, 7, 7, 3];
        const R_2: u128 = 17;

        const EXPECTED_G_R_2: u128 = 12;
        const EXPECTED_B_2: u128 = 0;

        const ZKP_3: [u128; 5] = [22, 14, 4, 20, 16];
        const V_3: [u128; 2] = [5, 24];
        const R_3: u128 = 30;
        const Q_RANDOM_WEIGHT: u128 = 1;

        const EXPECTED_Q_FINAL: u128 = 12;
        const EXPECTED_G_R_FINAL: u128 = 19;

        let pv_1: ProofVerifier<Fp31> = ProofVerifier::new(
            V_1.into_iter()
                .map(|x| Fp31::try_from(x).unwrap())
                .collect(),
            Fp31::try_from(OUT_1).unwrap(),
        );

        // first iteration
        let zkp_1 = ZeroKnowledgeProof::<Fp31, U7>::new(ZKP_1.map(|x| Fp31::try_from(x).unwrap()));

        let (b_share_1, pv_2) = pv_1.verify_proof::<U4>(&zkp_1, Fp31::try_from(R_1).unwrap());
        assert_eq!(b_share_1.as_u128(), EXPECTED_B_1);
        assert_eq!(
            pv_2.u_or_v.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            V_2,
        );
        assert_eq!(pv_2.out_share.as_u128(), EXPECTED_G_R_1);

        // second iteration
        let zkp_2 = ZeroKnowledgeProof::<Fp31, U7>::new(ZKP_2.map(|x| Fp31::try_from(x).unwrap()));

        let (b_share_2, pv_3) = pv_2.verify_proof::<U4>(&zkp_2, Fp31::try_from(R_2).unwrap());
        assert_eq!(b_share_2.as_u128(), EXPECTED_B_2);
        assert_eq!(
            pv_3.u_or_v.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            V_3,
        );
        assert_eq!(pv_3.out_share.as_u128(), EXPECTED_G_R_2);

        // final iteration
        let zkp_3 = ZeroKnowledgeProof::<Fp31, U5>::new(ZKP_3.map(|x| Fp31::try_from(x).unwrap()));

        let (q_final, out_share) = pv_3.verify_final_proof::<U2>(
            &zkp_3,
            Fp31::try_from(R_3).unwrap(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
        );

        assert_eq!(q_final.as_u128(), EXPECTED_Q_FINAL);
        assert_eq!(out_share.as_u128(), EXPECTED_G_R_FINAL);
    }
}
