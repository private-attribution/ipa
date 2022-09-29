use embed_doc_image::embed_doc_image;
/// Permutation reorders (1, 2, . . . , m) into (σ(1), σ(2), . . . , σ(m)).
/// For example, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is reordered into (C, D, B, A) by σ.
#[embed_doc_image("apply", "images/sort/apply.png")]
#[allow(dead_code)]
pub fn apply<T: Copy + Default>(sigma: &[usize], values: &[T]) -> Vec<T> {
    let mut applied_vec: Vec<T> = (0..sigma.len()).map(|_| Default::default()).collect();
    (0..sigma.len()).for_each(|i| {
        let idx = sigma[i];
        applied_vec[i] = values[idx];
    });
    applied_vec
}

/// To compute `apply_inv` on values, sigma(i) can be regarded as the destination of i, i.e., the i-th item is moved by `apply_inv`
/// to be the σ(i)-th item. Therefore, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is
/// reordered into (D, C, A, B).
#[embed_doc_image("apply_inv", "images/sort/apply_inv.png")]
#[allow(clippy::module_name_repetitions)]
#[allow(dead_code)]
pub fn apply_inv<T: Copy + Default>(sigma: &[usize], values: &[T]) -> Vec<T> {
    let mut applied_vec: Vec<T> = (0..sigma.len()).map(|_| Default::default()).collect();
    (0..sigma.len()).for_each(|i| {
        let idx = sigma[i];
        applied_vec[idx] = values[i];
    });
    applied_vec
}

#[cfg(test)]
mod tests {
    use super::{apply, apply_inv};

    #[test]
    fn apply_shares() {
        let values = ["A", "B", "C", "D"];
        let sigma = [2_usize, 3, 1, 0];
        let expected_output_apply = ["C", "D", "B", "A"];
        let output = apply(&sigma, &values);
        assert_eq!(output, expected_output_apply);

        let expected_output_apply_inv = ["D", "C", "A", "B"];
        let output = apply_inv(&sigma, &values);
        assert_eq!(output, expected_output_apply_inv);
    }
}
