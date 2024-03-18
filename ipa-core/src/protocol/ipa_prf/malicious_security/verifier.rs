use std::{
    iter::zip,
    ops::{Add, Sub},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::{Diff, Sum, U1};

use super::prover::{TwoNMinusOne, ZeroKnowledgeProof};
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

    pub fn verify_proof<λ: ArrayLength>(
        &self,
        zkp: ZeroKnowledgeProof<F, TwoNMinusOne<λ>>,
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

        let denominator_p = CanonicalLagrangeDenominator::<F, λ>::new();
        let lagrange_table_p_r = LagrangeTable::<F, λ, U1>::new(&denominator_p, &r);
        let p_or_q_r = (0..s)
            .map(|i| {
                let start = i * λ::USIZE;
                let end = start + λ::USIZE;
                let p_or_q = &self.u_or_v[start..end];
                lagrange_table_p_r.eval(p_or_q)[0]
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
}

#[cfg(all(test, unit_test))]
mod test {
    use typenum::{U4, U7};

    use super::ProofVerifier;
    use crate::{
        ff::{Fp31, U128Conversions},
        protocol::ipa_prf::malicious_security::prover::ZeroKnowledgeProof,
    };

    #[test]
    fn sample_proof() {
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

        const U_3: [u128; 2] = [3, 3];

        let pv_1: ProofVerifier<Fp31> = ProofVerifier::new(
            U_1.into_iter()
                .map(|x| Fp31::try_from(x).unwrap())
                .collect(),
            Fp31::try_from(OUT_1).unwrap(),
        );

        // first iteration
        let zkp_1 = ZeroKnowledgeProof::<Fp31, U7>::new(ZKP_1.map(|x| Fp31::try_from(x).unwrap()));

        let (b_share_1, pv_2) = pv_1.verify_proof::<U4>(zkp_1, Fp31::try_from(R_1).unwrap());
        assert_eq!(b_share_1.as_u128(), EXPECTED_B_1);
        assert_eq!(
            pv_2.u_or_v.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            U_2,
        );
        assert_eq!(pv_2.out_share.as_u128(), EXPECTED_G_R_1);

        // second iteration
        let zkp_2 = ZeroKnowledgeProof::<Fp31, U7>::new(ZKP_2.map(|x| Fp31::try_from(x).unwrap()));

        let (b_share_2, pv_3) = pv_2.verify_proof::<U4>(zkp_2, Fp31::try_from(R_2).unwrap());
        assert_eq!(b_share_2.as_u128(), EXPECTED_B_2);
        assert_eq!(
            pv_3.u_or_v.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            U_3,
        );
        assert_eq!(pv_3.out_share.as_u128(), EXPECTED_G_R_2);
    }
}
