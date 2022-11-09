use embed_doc_image::embed_doc_image;
use permutation::Permutation;

// TODO #OptimizeLater
// For now, we are using Permutation crate to implement `apply_inv` and `apply` functions.
// However this uses usize which is either 32-bit or 64-bit depending on the architecture we are using.
// In our case, if we are sorting less than 2^32 elements (over 4 billion) 32-bits is sufficient.
// We probably never need a 64-bit number and is not optimal.
// It would even be cool to use a u16 if you're sorting less than 65,000 items
// In future, we should plan to change this code to use u32 or u16 based on number of items

#[embed_doc_image("apply", "images/sort/apply.png")]
#[embed_doc_image("apply_inv", "images/sort/apply_inv.png")]
/// Permutation reorders (1, 2, . . . , m) into (σ(1), σ(2), . . . , σ(m)).
/// For example, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is reordered into (C, D, B, A) by σ.
/// ![Apply steps][apply]
pub fn apply<T: Copy + Default, S>(permutation: Permutation, values: &mut S)
where
    S: AsMut<[T]>,
{
    let mut permutation = permutation;
    permutation.apply_slice_in_place(values);
}

/// To compute `apply_inv` on values, permutation(i) can be regarded as the destination of i, i.e., the i-th item
/// is moved by `apply_inv` to be the σ(i)-th item. Therefore, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is
/// reordered into (D, C, A, B).
/// ![Apply inv steps][apply_inv]
pub fn apply_inv<T: Copy + Default, S>(permutation: Permutation, values: &mut S)
where
    S: AsMut<[T]>,
{
    let mut permutation = permutation;
    permutation.apply_inv_slice_in_place(values);
}

#[cfg(test)]
mod tests {
    use super::{apply, apply_inv};
    use permutation::Permutation;
    use rand::seq::SliceRandom;

    #[test]
    fn apply_shares() {
        let mut values = ["A", "B", "C", "D"];
        let indices = Permutation::oneline([2, 3, 1, 0]).inverse();
        let expected_output_apply = ["C", "D", "B", "A"];
        apply(indices, &mut values);
        assert_eq!(values, expected_output_apply);

        let mut values = ["A", "B", "C", "D"];
        let indices = Permutation::oneline([2, 3, 1, 0]).inverse();
        let expected_output_apply_inv = ["D", "C", "A", "B"];
        apply_inv(indices, &mut values);
        assert_eq!(values, expected_output_apply_inv);
    }

    #[test]
    pub fn composing() {
        let sigma = vec![4, 2, 0, 5, 1, 3];
        let mut rho = vec![3, 4, 0, 5, 1, 2];
        // Applying sigma on rho
        apply_inv(Permutation::oneline(sigma), &mut rho);
        assert_eq!(rho, vec![1, 0, 3, 2, 4, 5]);
    }

    #[test]
    pub fn apply_apply_inv_relation() {
        // This test shows that apply(permutation, values) is same as apply_inv(permutation.inverse(), values)
        let batchsize: usize = 100;
        let mut rng = rand::thread_rng();

        let mut permutation: Vec<usize> = (0..batchsize).collect();
        permutation.shuffle(&mut rng);

        let mut values: Vec<_> = (0..batchsize).collect();
        let mut values_copy = values.clone();

        apply(Permutation::oneline(permutation.clone()), &mut values);

        apply_inv(
            Permutation::oneline(permutation).inverse(),
            &mut values_copy,
        );

        assert_eq!(values, values_copy);
    }
}
