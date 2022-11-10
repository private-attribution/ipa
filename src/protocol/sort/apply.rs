use bitvec::bitvec;
use embed_doc_image::embed_doc_image;
use std::mem;

// TODO #OptimizeLater
// For now, we are using Permutation crate to implement `apply_inv` and `apply` functions.
// However this uses usize which is either 32-bit or 64-bit depending on the architecture we are using.
// In our case, if we are sorting less than 2^32 elements (over 4 billion) 32-bits is sufficient.
// We probably never need a 64-bit number and is not optimal.
// It would even be cool to use a u16 if you're sorting less than 65,000 items
// In future, we should plan to change this code to use u32 or u16 based on number of items

#[embed_doc_image("apply", "images/sort/apply.png")]
#[embed_doc_image("apply_inv", "images/sort/apply_inv.png")]
#[embed_doc_image("apply", "images/sort/apply.png")]
#[embed_doc_image("apply_inv", "images/sort/apply_inv.png")]

/// Permutation reorders (1, 2, . . . , m) into (σ(1), σ(2), . . . , σ(m)).
/// For example, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is reordered into (C, D, B, A) by σ.
/// ![Apply steps][apply]
pub fn apply<T: Copy + Default>(permutation: &[usize], values: &mut [T]) {
    let mut permuted = bitvec![0; permutation.len()];
    let mut tmp: T = T::default();

    for i in 0..permutation.len() {
        if permuted[i] == false {
            mem::swap(&mut tmp, &mut values[i]);
            let mut pos_i = i;
            let mut pos_j = permutation[pos_i];
            while pos_j != i {
                values[pos_i] = values[pos_j];
                pos_i = pos_j;
                pos_j = permutation[pos_i];
                permuted.set(pos_i, true);
            }
            mem::swap(&mut values[pos_i], &mut tmp);
            permuted.set(i, true);
        }
    }
}

/// To compute `apply_inv` on values, permutation(i) can be regarded as the destination of i, i.e., the i-th item
/// is moved by `apply_inv` to be the σ(i)-th item. Therefore, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is
/// reordered into (D, C, A, B).
/// ![Apply inv steps][apply_inv]
pub fn apply_inv<T: Copy + Default>(permutation: &[usize], values: &mut [T]) {
    let mut permuted = bitvec![0; permutation.len()];
    let mut tmp: T;

    for i in 0..permutation.len() {
        if permuted[i] == false {
            let mut destination = permutation[i];
            tmp = values[i];
            while destination != i {
                mem::swap(&mut tmp, &mut values[destination]);
                permuted.set(destination, true);
                destination = permutation[destination];
            }
            mem::swap(&mut values[i], &mut tmp);
            permuted.set(i, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{apply, apply_inv};

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
    pub fn composing() {
        let sigma = vec![4, 2, 0, 5, 1, 3];
        let mut rho = vec![3, 4, 0, 5, 1, 2];

        // Applying sigma on rho
        apply(&sigma, &mut rho);
        assert_eq!(rho, vec![1, 0, 3, 2, 4, 5]);
    }
}
