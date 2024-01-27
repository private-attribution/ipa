use crate::ff::{Field, Invert};

/// function for generating canonical evaluation points
/// overwrites `evaluation_points`
pub fn generate_evaluation_points<F>(evaluation_points: &mut [F]) -> ()
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
pub fn compute_lagrange_denominator<F>(evaluation_points: &[F], denominators: &mut [F]) -> ()
where
    F: Field + Invert,
{
    debug_assert_eq!(evaluation_points.len(), denominators.len());
    // check that differences are non-zero
    #[cfg(debug_assertions)]
    {
        for i in 0..evaluation_points.len() {
            for j in 0..evaluation_points.len() {
                debug_assert_eq!(
                    (
                        i,
                        j,
                        evaluation_points[i] - evaluation_points[j] != F::ZERO || j == i
                    ),
                    (i, j, true)
                )
            }
        }
    }
    // compute denominators:
    for i in 0..evaluation_points.len() {
        if i > 0 {
            for j in 0..i {
                denominators[i] *= evaluation_points[i] - evaluation_points[j];
            }
        }
        if i + 1 < evaluation_points.len() {
            for j in i + 1..evaluation_points.len() {
                denominators[i] *= evaluation_points[i] - evaluation_points[j];
            }
        }
        denominators[i] = denominators[i].invert();
    }
}

/// computes the lagrange base polynomials
/// for correctness, the denominators need to be consistent with the evaluation_points
/// overwrites `base`
pub fn compute_lagrange_base<F>(
    points: &[F],
    evaluation_points: &[F],
    denominators: &[F],
    base: &mut Vec<Vec<F>>,
) -> ()
where
    F: Field,
{
    debug_assert_eq!(evaluation_points.len(), denominators.len());
    #[cfg(debug_assertions)]
    {
        for base in base.iter() {
            debug_assert_eq!(evaluation_points.len(), base.len());
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
            for i in 0..evaluation_points.len() {
                if i > 0 {
                    for j in 0..i {
                        base[i] *= *point - evaluation_points[j];
                    }
                }
                if i + 1 < evaluation_points.len() {
                    for j in i + 1..evaluation_points.len() {
                        base[i] *= *point - evaluation_points[j];
                    }
                }
            }
        });
}

/// precomputed lagrange evaluation
/// evaluates polynomial using base polynomials
/// multiplies `result` with input `result`, i.e. use input `F::ONE`
pub fn lagrange_evaluation_precomputed<F>(y: &[F], base: &Vec<Vec<F>>, result: &mut [F]) -> ()
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
/// given points `(x_0,y_0),...,(x_n,y_0)` on a polynomial `p`
/// and points `p_0,...,p_m`
/// compute `result_0=result_0*p(p_0),...,result_m=result_m*p(p_m)`
/// It uses the lagrange method to compute the points `https://en.wikipedia.org/wiki/Lagrange_polynomial`
/// further, rather than outputting `p(p_k)`, we set `result_k=result_k*p(p_k)`
/// which fits better to how we use `p(p_k)`
pub fn lagrange_evaluation<F>(x: &[F], y: &[F], p: &[F], result: &mut [F]) -> ()
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
    fn lagrange_evaluation_fp25519() {
        let mut rng = thread_rng();
        let evaluation_points_size = rng.gen::<usize>() % 100;
        let mut evaluation_points = vec![Fp25519::ONE; evaluation_points_size];
        evaluation_points
            .iter_mut()
            .for_each(|x| *x = rng.gen::<Fp25519>());
        let mut y_values = vec![Fp25519::ONE; evaluation_points_size];
        y_values.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());
        let mut evaluated_y = vec![Fp25519::ONE; evaluation_points_size];
        lagrange_evaluation(
            &evaluation_points,
            &y_values,
            &evaluation_points,
            &mut evaluated_y,
        );

        // test evaluation at interpolation points
        assert_eq!(evaluated_y, y_values);

        // sample random polynomial in monomial form of degree `evaluation_points_size`
        let mut polynomial = vec![Fp25519::ONE; evaluation_points_size];
        polynomial
            .iter_mut()
            .for_each(|x| *x = rng.gen::<Fp25519>());
        // add random point to evaluation points
        evaluation_points.push(rng.gen::<Fp25519>());

        // evaluate polynomial at evaluation_points
        let mut y_values = vec![Fp25519::ZERO; evaluation_points_size + 1];
        evaluation_points.iter().for_each(|x_value| {
            let mut base = Fp25519::ONE;
            polynomial.iter().for_each(|coefficient| {
                y_values.iter_mut().for_each(|y| *y = *coefficient * base);
                base *= *x_value
            })
        });

        // lagrange evaluate at random point
        evaluated_y[0] = Fp25519::ONE;
        lagrange_evaluation(
            &evaluation_points[0..evaluation_points_size],
            &y_values[0..evaluation_points_size],
            std::slice::from_ref(&evaluation_points[evaluation_points_size]),
            std::slice::from_mut(&mut evaluated_y[0]),
        );

        // check equality
        assert_eq!(y_values[evaluation_points_size], evaluated_y[0]);
    }

    #[test]
    fn lagrange_precomputed_test() {
        let mut rng = thread_rng();
        let evaluation_points_size = rng.gen::<usize>() % 100;
        let mut evaluation_points_random = vec![Fp25519::ONE; evaluation_points_size];
        evaluation_points_random
            .iter_mut()
            .for_each(|x| *x = rng.gen::<Fp25519>());
        let mut evaluation_points_canonical = vec![Fp25519::ONE; evaluation_points_size];
        generate_evaluation_points(&mut evaluation_points_canonical);
        let mut y_values = vec![Fp25519::ONE; evaluation_points_size];
        y_values.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());
        let points_size = rng.gen::<usize>() % 100;
        let mut points_random = vec![Fp25519::ONE; points_size];
        points_random.iter_mut().for_each(|y| *y = rng.gen::<Fp25519>());

        for evaluation_points in [&evaluation_points_random, &evaluation_points_canonical] {
            // non-precomputed
            let mut evaluated_y = vec![Fp25519::ONE; points_size];
            lagrange_evaluation(
                &evaluation_points,
                &y_values,
                &points_random,
                &mut evaluated_y,
            );

            // precomputed
            let mut evaluated_y_precomputed = vec![Fp25519::ONE; points_size];
            let mut denominators = vec![Fp25519::ONE; evaluation_points_size];
            compute_lagrange_denominator(&evaluation_points, &mut denominators);
            let mut base = vec![vec![Fp25519::ONE; evaluation_points_size]; points_size];
            compute_lagrange_base(&points_random, &evaluation_points, &denominators, &mut base);
            lagrange_evaluation_precomputed(&y_values, &base, &mut evaluated_y_precomputed);

            evaluated_y
                .iter()
                .zip(evaluated_y_precomputed.iter())
                .for_each(|(x, y)| assert_eq!(*x, *y));
        }
    }
}
