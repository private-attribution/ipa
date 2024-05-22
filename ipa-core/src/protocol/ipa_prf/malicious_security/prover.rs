use std::{
    borrow::Borrow,
    iter::zip,
    ops::{Add, Sub},
};

use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use typenum::{Diff, Sum, U1};

use crate::{
    error::Error,
    ff::PrimeField,
    helpers::hashing::{compute_hash, hash_to_field},
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

pub type UVPolynomial<F, N> = (GenericArray<F, N>, GenericArray<F, N>);
pub type TwoNMinusOne<R> = Diff<Sum<R, R>, U1>;

// todo: deprecate since final proof is no longer needed and only final proof uses this
pub type TwoNPlusOne<R> = Sum<Sum<R, R>, U1>;

/// The purpose of this trait is to define an associated type,
/// i.e. the length of the array `Length`
pub trait ProofArray {
    type Length: ArrayLength;
}

/// This struct contains a single `ZeroKnowledgeProof`
/// The length of the proof is not the generic parameter `R`.
/// The length can be obtained using the trait `ProofArray`
/// where the associated type `Length`
/// represents the length of the proof.
///
/// Parameter `R` represents the recursion factor, which is a parameter
/// used during the proof generation and verification.
#[derive(Debug)]
pub struct ZeroKnowledgeProof<F, R>
where
    Self: ProofArray,
    F: PrimeField,
    <Self as ProofArray>::Length: ArrayLength,
{
    pub g: GenericArray<F, <Self as ProofArray>::Length>,
}

impl<F, R> ProofArray for ZeroKnowledgeProof<F, R>
where
    F: PrimeField,
    R: Add + ArrayLength,
    <R as Add>::Output: Sub<U1>,
    <<R as Add>::Output as Sub<U1>>::Output: ArrayLength,
{
    type Length = TwoNMinusOne<R>;
}

impl<F, R> Default for ZeroKnowledgeProof<F, R>
where
    F: PrimeField,
    Self: ProofArray,
{
    fn default() -> Self {
        ZeroKnowledgeProof {
            g: GenericArray::<F, <Self as ProofArray>::Length>::generate(|_| F::ZERO),
        }
    }
}

impl<F, R> ZeroKnowledgeProof<F, R>
where
    F: PrimeField,
    Self: ProofArray,
{
    // todo: deprecate
    pub fn new<I>(g: I) -> Self
    where
        I: IntoIterator<Item = F>,
    {
        ZeroKnowledgeProof {
            g: g.into_iter().collect(),
        }
    }

    /// Distributed Zero Knowledge Proofs algorithm drawn from
    /// `https://eprint.iacr.org/2023/909.pdf`
    ///
    /// Uses Andy's borrow trick to work with references and owned values :)
    pub fn compute_proof<J, B>(
        uv: J,
        lagrange_table: &LagrangeTable<F, R, <R as Sub<U1>>::Output>,
    ) -> Self
    where
        J: Iterator<Item = B>,
        R: ArrayLength + Sub<U1>,
        <R as Sub<U1>>::Output: ArrayLength,
        B: Borrow<UVPolynomial<F, R>>,
    {
        let mut proof = Self::default();
        for uv in uv {
            for i in 0..R::USIZE {
                proof.g[i] += uv.borrow().0[i] * uv.borrow().1[i];
            }
            let p_extrapolated = lagrange_table.eval(&uv.borrow().0);
            let q_extrapolated = lagrange_table.eval(&uv.borrow().1);

            for (i, (x, y)) in
                zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate()
            {
                proof.g[R::USIZE + i] += x * y;
            }
        }
        proof
    }
}

#[derive(Debug)]
pub struct UVStore<F, R>
where
    F: PrimeField,
    R: ArrayLength,
{
    uv: Vec<UVPolynomial<F, R>>,
}

impl<F, R> UVStore<F, R>
where
    F: PrimeField,
    R: ArrayLength,
{
    pub fn len(&self) -> usize {
        self.uv.len() * R::USIZE
    }

    pub fn is_empty(&self) -> bool {
        self.uv.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &UVPolynomial<F, R>> + Clone {
        self.uv.iter()
    }

    /// This function returns the first tuple.
    pub fn first(&self) -> &UVPolynomial<F, R> {
        &self.uv[0]
    }

    /// This function returns the first tuple as mutable reference.
    pub fn first_mut(&mut self) -> &mut UVPolynomial<F, R> {
        &mut self.uv[0]
    }

    /// This function returns the first `p` polynomial,
    /// i.e. the polynomial on the left of the first tuple.
    pub fn first_p(&self) -> &GenericArray<F, R> {
        &self.first().0
    }

    /// This function returns the first `q` polynomial,
    /// i.e. the polynomial on the right of the first tuple.
    pub fn first_q(&self) -> &GenericArray<F, R> {
        &self.first().1
    }

    /// This function returns the first `p` polynomial,
    /// i.e. the polynomial on the left of the first tuple.
    pub fn first_p_mut(&mut self) -> &mut GenericArray<F, R> {
        &mut self.first_mut().0
    }

    /// This function returns the first `q` polynomial,
    /// i.e. the polynomial on the right of the first tuple.
    pub fn first_q_mut(&mut self) -> &mut GenericArray<F, R> {
        &mut self.first_mut().1
    }

    /// This function allows to set masks to protect sensitive information.
    /// It is used when the last proof of a batch is generated.
    ///
    /// ## Panics
    /// Panics when `self` contains more than one polynomial tuple
    /// or when masks cannot be set safely.
    /// The latter is the case when there are too many points for a polynomial of degree `R minus 1`.
    /// This function likely panics when used with small fields like `Fp31`
    /// Use `FP61BitPrime` instead when using this function in test cases.
    pub fn set_masks(&mut self, p_0: F, q_0: F) -> Result<(), Error> {
        // assert that there are only two polynomials
        if self.uv.len() != 1usize {
            return Err(Error::DZKPMasksLength);
        }
        debug_assert_eq!(self.uv.len(), 1usize);
        // assert that last point of p,q is really `F::Zero`
        // such that we can safely set the 0 points to be the last points
        // p is the polynomial uv_store.first().0
        // and q is the polynomial uv_store.first().1
        // this is likely to fail for small sized fields,
        // so dont use Fp31 (but rather FP61BitPrime) in tests for this function.
        if (self.first_p()[R::USIZE - 1], self.first_q()[R::USIZE - 1]) != (F::ZERO, F::ZERO) {
            return Err(Error::DZKPMasks);
        }
        // shift 0 positions to the back where no actual point is stored
        // (F::ZERO are overwhelmingly likely to be just 0 fillers)
        self.first_p_mut()[R::USIZE - 1] = self.first_p()[0];
        self.first_q_mut()[R::USIZE - 1] = self.first_q()[0];
        // set 0 positions of p, q polynomial to masks
        self.first_p_mut()[0] = p_0;
        self.first_q_mut()[0] = q_0;

        Ok(())
    }

    /// This function generates a set of `UVPolynomial<F,R>` that is used for the next recursion.
    /// Parameter `R` determines the degree of the polynomial which is `R-1`.
    /// It also determines the amount of points that represent each polynomial which is `R`.
    ///
    /// The function uses `Fiat-Shamir` to generate a challenge `r`
    /// by hashing the two input proofs, `proof_left` and `proof_right`
    /// It then evaluates each input polynomial at x coordinate `r`.
    /// The computed points are used to generate the set of `UVPolynomial<F,M>`.
    ///
    /// Uses Andy's borrow trick to work with references and owned values :)
    pub fn gen_challenge_and_recurse<J, B>(
        proof_left: &ZeroKnowledgeProof<F, R>,
        proof_right: &ZeroKnowledgeProof<F, R>,
        mut uv: J,
    ) -> Self
    where
        F: Default,
        ZeroKnowledgeProof<F, R>: ProofArray,
        J: Iterator<Item = B>,
        B: Borrow<UVPolynomial<F, R>>,
    {
        let lagrange_table_r = Self::retrieve_lagrange_table(proof_left, proof_right);

        let mut output = Vec::<UVPolynomial<F, R>>::new();

        // iter over chunks of size R
        // and interpolate at x coordinate r
        while let Some(polynomial) = uv.next() {
            let mut u = GenericArray::<F, R>::default();
            let mut v = GenericArray::<F, R>::default();
            u[0] = lagrange_table_r.eval(&polynomial.borrow().0)[0];
            v[0] = lagrange_table_r.eval(&polynomial.borrow().1)[0];
            for i in 1..R::USIZE {
                if let Some(polynomial) = uv.next() {
                    u[i] = lagrange_table_r.eval(&polynomial.borrow().0)[0];
                    v[i] = lagrange_table_r.eval(&polynomial.borrow().1)[0];
                } else {
                    u[i] = F::ZERO;
                    v[i] = F::ZERO;
                }
            }
            output.push((u, v));
        }

        Self { uv: output }
    }

    /// This function computes a `LagrangeTable` for a `Fiat-Shamir` challenge
    /// which is computed via hashing `proof_left` and `proof_right`
    fn retrieve_lagrange_table(
        proof_left: &ZeroKnowledgeProof<F, R>,
        proof_right: &ZeroKnowledgeProof<F, R>,
    ) -> LagrangeTable<F, R, U1>
    where
        ZeroKnowledgeProof<F, R>: ProofArray,
    {
        let r: F = hash_to_field(
            &compute_hash(proof_left.g.iter()),
            &compute_hash(proof_right.g.iter()),
            R::U128,
        );

        let denominator = CanonicalLagrangeDenominator::<F, R>::new();
        LagrangeTable::<F, R, U1>::new(&denominator, &r)
    }
}

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
