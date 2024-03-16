use ipa_macros::Step;

use crate::{ff::PrimeField, protocol::{prss::SharedRandomness, RecordId}};

use super::Context;

pub struct MaliciousZeroKnowledgeProofValidator {
    x_left: u64,
    x_right: u64,
    y_left: u64,
    y_right: u64,
    p_left: u64,
    p_right: u64,
    z: u64,
}

#[derive(Step)]
pub(crate) enum Step {
    RandomYIntercepts,
}

impl MaliciousZeroKnowledgeProofValidator {
    fn recursive_validate<C, F>(ctx: C, m: usize, lambda: usize, u: &[F], v: &[F])
    where
        F: PrimeField,
        C: Context + SharedRandomness,
    {
        let out = -F::truncate_from(m.into()) * F::INV_2;
        let m_prime = 4 * m;
        let mut s = m_prime / lambda;
        if m_prime % lambda != 0 {
            s += 1;
        }

        // (a)
        for k in 0..lambda {
            if (s - 1) * lambda + k > m_prime {
                u[(s - 1) * lambda + k] = F::ZERO; // I'm not sure about the `s-1` part...
                v[(s - 1) * lambda + k] = F::ZERO;
            }
        }

        // (b)
        let polynomials_p = Vec::with_capacity(s);
        let polynomials_q = Vec::with_capacity(s);
        let num_points = lambda + (s == 1).into();
        let mut p_points = vec![F::ZERO; num_points];
        let mut q_points = vec![F::ZERO; num_points];
        let c_random_weights = ctx.narrow(&Step::RandomYIntercepts);

        for t in 0..s {
            if s == 1 {
                let (left_rand, right_rand) = c_random_weights.generate_fields(RecordId::from(t));
                p_points[0] = right_rand;
                q_points[0] = left_rand;
            }
            for k in 0..lambda {
                let idx = k + (s == 1).into();
                p_points[idx] = u[t * lambda + k];
                q_points[idx] = v[t * lambda + k];
            }

            polynomials_p.push(fit_polynomial(p_points, false));
            polynomials_q.push(fit_polynomial(q_points, false));
        }
    }

    // right now, hard-coded to validate a batch of 64
    fn gen_uv_for_batch<F: PrimeField>(self) -> ([F; 256], [F; 256]) {
        // a^(ℓ) := x^(ℓ)_i
        let a = self.x_right;

        // c^(ℓ) := y^(ℓ)_i
        let c = self.y_right;

        // e^(ℓ) := x^(ℓ)_i · y^(ℓ)_i ⊕ z^(ℓ)_i ⊕ ρ^(ℓ)_i
        let e = (self.x_right & self.y_right) ^ self.z ^ self.p_right;

        // b^(ℓ) := y^(ℓ)_(i−1)
        let b = self.y_left;

        // d^(ℓ) := x^(ℓ)_(i−1)
        let d = self.x_left;

        // f^(ℓ) := ρ^(ℓ)_(i−1)
        let f = self.p_left;

        let mut u: [F; 256] = [F::ZERO; 256];
        let mut v: [F; 256] = [F::ZERO; 256];

        let neg_2 = F::try_from(F::PRIME.into() - 2).unwrap();
        for i in 0..64 {
            let a_i = F::truncate_from((a >> i) & 1);
            let c_i = F::truncate_from((c >> i) & 1);
            let one_minus_2e = F::ONE + F::truncate_from((e >> i) & 1) * neg_2;
            // g^(ℓ)_1 := −2a^(ℓ) · c^(ℓ) · (1 − 2e^(ℓ))
            u[4 * i] = a_i * neg_2 * c_i * one_minus_2e;

            // g^(ℓ)_2 := c^(ℓ) · (1 − 2e^(ℓ))
            u[4 * i + 1] = c_i * one_minus_2e;

            // g^(ℓ)_3 := a^(ℓ) · (1 − 2e^(ℓ))
            u[4 * i + 2] = a_i * one_minus_2e;

            // g^(ℓ)_4 := −(1−2e^(ℓ))/2,
            u[4 * i + 3] = -one_minus_2e * F::INV_2;

            let b_i = F::truncate_from((b >> i) & 1);
            let d_i = F::truncate_from((d >> i) & 1);
            let one_minus_2f = F::ONE + F::truncate_from((f >> i) & 1) * neg_2;

            // h^(ℓ)_1 := b^(ℓ) · d^(ℓ) · (1 − 2 f^(ℓ))
            v[4 * i] = b_i * d_i * one_minus_2f;

            // h^(ℓ)_2 := d^(ℓ) · (1 − 2 f^(ℓ))
            v[4 * i + 1] = d_i * one_minus_2f;

            // h^(ℓ)_3 := b^(ℓ) · (1 − 2 f^(ℓ))
            v[4 * i + 2] = b_i * one_minus_2f;

            // h^(ℓ)_4 := 1−2 f^(ℓ)
            v[4 * i + 3] = one_minus_2f;
        }

        (u, v)
    }
}
