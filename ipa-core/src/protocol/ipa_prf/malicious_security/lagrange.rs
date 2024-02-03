use crate::ff::{Field, Invert};

/// function for generating canonical evaluation points
/// overwrites `evaluation_points`
pub fn generate_evaluation_points<F>(evaluation_points: &mut [F])
where
    F: Field,
{
    // check that field is large enough to hold evaluation points
    debug_assert!(F::BITS > usize::BITS - evaluation_points.len().leading_zeros() + 1);
    // compute evaluation points `0`, `1`, `2`, ...
    evaluation_points
        .iter_mut()
        .enumerate()
        .for_each(|(i, p)| *p = F::try_from(i as u128).unwrap());
}

/// computes the lagrange denominators for the base polynomials
/// the denominators change for different evaluation points
/// the function multiplies the denominators to `denominators`, i.e. input `F::ONE`
pub fn compute_lagrange_denominator<F>(evaluation_points: &[F], denominators: &mut [F])
where
    F: Field + Invert,
{
    debug_assert_eq!(evaluation_points.len(), denominators.len());
    // check that differences are non-zero
    #[cfg(debug_assertions)]
    {
        evaluation_points.iter().enumerate().for_each(|i| {
            evaluation_points.iter().enumerate().for_each(|j| {
                assert_eq!(
                    (i.0, j.0, true),
                    (i.0, j.0, *i.1 - *j.1 != F::ZERO || j.0 == i.0)
                )
            })
        });
    }
    // compute denominators:
    denominators
        .iter_mut()
        .zip(evaluation_points.iter().enumerate())
        .for_each(|(d, i)| {
            evaluation_points
                .iter()
                .enumerate()
                .filter(|&j| j.0 != i.0)
                .for_each(|j| *d *= *i.1 - *j.1);
            *d = d.invert()
        });
}

/// computes the lagrange base polynomials, see `https://en.wikipedia.org/wiki/Lagrange_polynomial`
/// for correctness, the denominators need to be consistent with the evaluation_points
/// overwrites `base`
pub fn compute_lagrange_base<F>(
    points: &[F],
    evaluation_points: &[F],
    denominators: &[F],
    base: &mut Vec<Vec<F>>,
) where
    F: Field,
{
    debug_assert_eq!(evaluation_points.len(), denominators.len());
    #[cfg(debug_assertions)]
    {
        for base in base.iter() {
            assert_eq!(evaluation_points.len(), base.len());
        }
    }
    debug_assert_eq!(points.len(), base.len());

    // for each point, compute base polynomials
    points
        .iter()
        .zip(base.iter_mut())
        .for_each(|(point, base)| {
            // set up the denominators
            base.copy_from_slice(denominators);
            // compute the nominator
            base.iter_mut().enumerate().for_each(|b| {
                evaluation_points
                    .iter()
                    .enumerate()
                    .filter(|&j| j.0 != b.0)
                    .for_each(|j| {
                        *b.1 *= *point - *j.1;
                    });
            });
        });
}

/// precomputed lagrange evaluation
/// evaluates polynomial using base polynomials
/// the base polynomials are tied to specific evaluation points
/// multiplies `result` with input `result`, i.e. use input `F::ONE`
pub fn lagrange_evaluation_precomputed<F>(y: &[F], base: &Vec<Vec<F>>, result: &mut [F])
where
    F: Field,
{
    debug_assert_eq!(base.len(), result.len());
    #[cfg(debug_assertions)]
    {
        for base in base.iter() {
            debug_assert_eq!(y.len(), base.len());
        }
    }
    result
        .iter_mut()
        .zip(base.iter())
        .for_each(|(result, base)| {
            *result *= base
                .iter()
                .zip(y.iter())
                .fold(F::ZERO, |acc, (base, y)| acc + *base * *y)
        });
}

/// lagrange evaluation
/// given points `(x_0,y_0),...,(x_n,y_n)` on a polynomial `p` and points `p_0,...,p_m`
/// the function computes `p` evaluated on points `p_0,...,p_m`
///
/// It follows the lagrange method to compute the points `https://en.wikipedia.org/wiki/Lagrange_polynomial`
/// further, rather than outputting `p(p_k)`, we set `result_k=result_k*p(p_k)`
/// which fits better to how we use `p(p_k)`
pub fn lagrange_evaluation<F>(x: &[F], y: &[F], p: &[F], result: &mut [F])
where
    F: Field + Invert,
{
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(p.len(), result.len());
    #[cfg(debug_assertions)]
    {
        for i in 0..x.len() {
            for j in 0..x.len() {
                debug_assert_eq!((i, j, x[i] - x[j] != F::ZERO || j == i), (i, j, true))
            }
        }
    }

    // compute denominators:
    let mut denominators = vec![F::ONE; x.len()];
    for i in 0..x.len() {
        if i > 0 {
            for j in 0..i {
                denominators[i] *= x[i] - x[j];
            }
        }
        if i + 1 < x.len() {
            for j in i + 1..x.len() {
                denominators[i] *= x[i] - x[j];
            }
        }
        denominators[i] = denominators[i].invert();
    }

    for k in 0..p.len() {
        // evaluate polynomial on point p_k, i.e. compute `p(p_k)` use Lagrange formula
        let mut sum = F::ZERO;
        for i in 0..x.len() {
            let mut basis_polynomial = denominators[i] * y[i];
            if i > 0 {
                for j in 0..i {
                    basis_polynomial *= p[k] - x[j];
                }
            }
            if i + 1 < x.len() {
                for j in i + 1..x.len() {
                    basis_polynomial *= p[k] - x[j];
                }
            }
            sum += basis_polynomial;
        }
        // compute "result_k = result_k * p(p_k)"
        result[k] *= sum;
    }
}

mod test {
    use rand::{thread_rng, Rng};

    use crate::{
        ff::ec_prime_field::Fp25519,
        protocol::ipa_prf::malicious_security::lagrange::{
            compute_lagrange_base, compute_lagrange_denominator, generate_evaluation_points,
            lagrange_evaluation, lagrange_evaluation_precomputed,
        },
        secret_sharing::SharedValue,
    };

    #[test]
    fn consistency_at_evaluation_points_test() {
        // use random evaluation points
        let mut rng = thread_rng();
        let e_p_size = rng.gen::<usize>() % 20;
        let mut e_p = vec![Fp25519::ONE; e_p_size];
        e_p.iter_mut().for_each(|x| *x = rng.gen::<Fp25519>());

        // generate random polynomial q
        // which is represented by points on q
        // where the x coordinates are the evaluation points
        let mut q = vec![Fp25519::ONE; e_p_size];
        q.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());

        // check consistency of q at the interpolation points
        let mut e_y = vec![Fp25519::ONE; e_p_size];
        lagrange_evaluation(&e_p, &q, &e_p, &mut e_y);
        assert_eq!(e_y, q);
    }

    #[test]
    fn consistency_with_monomial_base_polynomial_test() {
        // use random evaluation points
        let mut rng = thread_rng();
        let e_p_size = rng.gen::<usize>() % 20;
        let mut e_p = vec![Fp25519::ONE; e_p_size];
        e_p.iter_mut().for_each(|x| *x = rng.gen::<Fp25519>());

        // sample random polynomial p in monomial form, i.e. `sum coefficient_k * x^k`,
        // of degree `evaluation_points_size`
        let mut p = vec![Fp25519::ONE; e_p_size];
        p.iter_mut().for_each(|x| *x = rng.gen::<Fp25519>());
        // add random point to evaluation points
        e_p.push(rng.gen::<Fp25519>());

        // evaluate polynomial p at evaluation_points and random point using monomial base
        let mut y_values = vec![Fp25519::ZERO; e_p_size + 1];
        e_p.iter().for_each(|x_value| {
            // monomial base, i.e. `x^k`
            let mut base = Fp25519::ONE;
            // evaluate p via `sum coefficient_k * x^k`
            p.iter().for_each(|coefficient| {
                y_values.iter_mut().for_each(|y| *y = *coefficient * base);
                base *= *x_value
            })
        });

        // lagrange evaluate p at random point
        let mut e_y = Fp25519::ONE;
        lagrange_evaluation(
            &e_p[0..e_p_size],
            &y_values[0..e_p_size],
            std::slice::from_ref(&e_p[e_p_size]),
            std::slice::from_mut(&mut e_y),
        );

        // check equality between "monomial evaluation" and "Lagrange evaluation"
        assert_eq!(y_values[e_p_size], e_y);
    }

    #[test]
    fn lagrange_precomputed_canonical_test() {
        let mut rng = thread_rng();

        // generate canonical evaluation points
        let e_p_size = rng.gen::<usize>() % 20;
        let mut e_p = vec![Fp25519::ONE; e_p_size];
        generate_evaluation_points(&mut e_p);

        // random polynomial p
        let mut q = vec![Fp25519::ONE; e_p_size];
        q.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());

        // generate random points
        let r_p_size = rng.gen::<usize>() % 20;
        let mut r_p = vec![Fp25519::ONE; r_p_size];
        r_p.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());

        // non-precomputed
        let mut evaluated_q = vec![Fp25519::ONE; r_p_size];
        lagrange_evaluation(&e_p, &q, &r_p, &mut evaluated_q);

        // precomputed
        let mut evaluated_q_precomputed = vec![Fp25519::ONE; r_p_size];
        let mut denominators = vec![Fp25519::ONE; e_p_size];
        compute_lagrange_denominator(&e_p, &mut denominators);
        let mut base = vec![vec![Fp25519::ONE; e_p_size]; r_p_size];
        compute_lagrange_base(&r_p, &e_p, &denominators, &mut base);
        lagrange_evaluation_precomputed(&q, &base, &mut evaluated_q_precomputed);

        evaluated_q
            .iter()
            .zip(evaluated_q_precomputed.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn lagrange_precomputed_random_test() {
        let mut rng = thread_rng();

        // generate random evaluation points
        let e_p_size = rng.gen::<usize>() % 20;
        let mut e_p_r = vec![Fp25519::ONE; e_p_size];
        e_p_r.iter_mut().for_each(|x| *x = rng.gen::<Fp25519>());

        // generate random polynomial
        let mut q = vec![Fp25519::ONE; e_p_size];
        q.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());

        // generate random points
        let p_size = rng.gen::<usize>() % 20;
        let mut r_p = vec![Fp25519::ONE; p_size];
        r_p.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());

        // non-precomputed
        let mut evaluated_q = vec![Fp25519::ONE; p_size];
        lagrange_evaluation(&e_p_r, &q, &r_p, &mut evaluated_q);

        // precomputed
        let mut evaluated_q_precomputed = vec![Fp25519::ONE; p_size];
        let mut denominators = vec![Fp25519::ONE; e_p_size];
        compute_lagrange_denominator(&e_p_r, &mut denominators);
        let mut base = vec![vec![Fp25519::ONE; e_p_size]; p_size];
        compute_lagrange_base(&r_p, &e_p_r, &denominators, &mut base);
        lagrange_evaluation_precomputed(&q, &base, &mut evaluated_q_precomputed);

        evaluated_q
            .iter()
            .zip(evaluated_q_precomputed.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }
}
