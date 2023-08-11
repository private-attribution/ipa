use bitvec::bitvec;
use embed_doc_image::embed_doc_image;

#[embed_doc_image("apply", "images/sort/apply.png")]
/// Permutation reorders (1, 2, . . . , m) into (σ(1), σ(2), . . . , σ(m)).
/// For example, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is reordered into (C, D, B, A) by σ.
///
/// ![Apply steps][apply]
pub fn apply<T>(permutation: &[u32], values: &mut [T]) {
    debug_assert!(permutation.len() == values.len());
    let mut permuted = bitvec![0; permutation.len()];

    for i in 0..permutation.len() {
        if !permuted[i] {
            let mut pos_i = i;
            let mut pos_j = permutation[pos_i] as usize;
            while pos_j != i {
                values.swap(pos_i, pos_j);
                permuted.set(pos_j, true);
                pos_i = pos_j;
                pos_j = permutation[pos_i] as usize;
            }
        }
    }
}

#[embed_doc_image("applyinv", "images/sort/apply_inv.png")]
/// To compute `apply_inv` on values, permutation(i) can be regarded as the destination of i, i.e., the i-th item
/// is moved by `apply_inv` to be the σ(i)-th item. Therefore, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is
/// reordered into (D, C, A, B).
///
/// ![Apply inv steps][applyinv]
pub fn apply_inv<T>(permutation: &[u32], values: &mut [T]) {
    assert_eq!(permutation.len(), values.len());
    let mut permuted = bitvec![0; permutation.len()];

    for i in 0..permutation.len() {
        if !permuted[i] {
            let mut destination = permutation[i] as usize;
            while destination != i {
                values.swap(i, destination);
                permuted.set(destination, true);
                destination = permutation[destination] as usize;
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::seq::SliceRandom;

    use super::{apply, apply_inv};
    use crate::rand::thread_rng;

    #[test]
    fn apply_just_one_cycle() {
        let mut values = ["A", "B", "C", "D"];
        let permutation = [2, 3, 1, 0];
        let expected_output_apply = ["C", "D", "B", "A"];
        apply(&permutation, &mut values);
        assert_eq!(values, expected_output_apply);
    }

    #[test]
    fn apply_just_two_cycles() {
        let mut values = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"];
        let permutation = [3, 4, 6, 7, 0, 9, 10, 1, 2, 8, 5];
        let expected_output_apply = ["D", "E", "G", "H", "A", "J", "K", "B", "C", "I", "F"];
        apply(&permutation, &mut values);
        assert_eq!(values, expected_output_apply);
    }

    #[test]
    fn apply_complex() {
        let mut values = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"];
        let permutation = [1, 0, 2, 5, 6, 7, 8, 9, 10, 3, 4];
        let expected_output_apply = ["B", "A", "C", "F", "G", "H", "I", "J", "K", "D", "E"];
        apply(&permutation, &mut values);
        assert_eq!(values, expected_output_apply);
    }

    #[test]
    fn apply_inv_just_one_cycle() {
        let mut values = ["A", "B", "C", "D"];
        let permutation = [2, 3, 1, 0];
        let expected_output_apply = ["D", "C", "A", "B"];
        apply_inv(&permutation, &mut values);
        assert_eq!(values, expected_output_apply);
    }

    #[test]
    fn apply_inv_just_two_cycles() {
        let mut values = ["A", "B", "C", "D", "E"];
        let permutation = [3, 4, 1, 0, 2];
        let expected_output_apply = ["D", "C", "E", "A", "B"];
        apply_inv(&permutation, &mut values);
        assert_eq!(values, expected_output_apply);
    }

    #[test]
    fn apply_inv_complex() {
        let mut values = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"];
        let permutation = [1, 0, 2, 5, 6, 7, 8, 9, 10, 3, 4];
        let expected_output_apply = ["B", "A", "C", "J", "K", "D", "E", "F", "G", "H", "I"];
        apply_inv(&permutation, &mut values);
        assert_eq!(values, expected_output_apply);
    }

    #[test]
    fn permutations_super_long() {
        const SUPER_LONG: usize = 16 * 16 * 16 * 16; // 65,536
        let mut original_values = Vec::with_capacity(SUPER_LONG);
        for i in 0..SUPER_LONG {
            original_values.push(format!("{i:#06x}"));
        }
        let mut permutation: Vec<u32> = (0..SUPER_LONG)
            .map(|i| usize::try_into(i).unwrap())
            .collect();
        let mut rng = thread_rng();
        permutation.shuffle(&mut rng);

        let mut after_apply = original_values.clone();
        apply(&permutation, &mut after_apply);
        for i in 0..SUPER_LONG {
            assert_eq!(after_apply[i], original_values[permutation[i] as usize]);
        }

        let mut after_apply_inv = original_values.clone();
        apply_inv(&permutation, &mut after_apply_inv);
        for i in 0..SUPER_LONG {
            assert_eq!(original_values[i], after_apply_inv[permutation[i] as usize]);
        }
    }

    #[test]
    pub fn composing() {
        let sigma = vec![4, 2, 0, 5, 1, 3];
        let mut rho = vec![3, 4, 0, 5, 1, 2];

        // Applying sigma on rho
        apply(&sigma, &mut rho);
        assert_eq!(rho, vec![1, 0, 3, 2, 4, 5]);
    }
}
