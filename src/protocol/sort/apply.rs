use embed_doc_image::embed_doc_image;
use permutation::Permutation;

// TODO #OptimizeLater
// For now, we are using Permutation crate tp implement `apply_inv` and `apply` functions.
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
#[allow(dead_code)]
pub fn apply<T: Copy + Default, S>(permutation: &mut Permutation, values: &mut S)
where
    S: AsMut<[T]>,
{
    permutation.apply_slice_in_place(values);
}

/// To compute `apply_inv` on values, permutation(i) can be regarded as the destination of i, i.e., the i-th item
/// is moved by `apply_inv` to be the σ(i)-th item. Therefore, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is
/// reordered into (D, C, A, B).
/// ![Apply inv steps][apply_inv]
#[allow(clippy::module_name_repetitions, dead_code)]
pub fn apply_inv<T: Copy + Default, S>(permutation: &mut Permutation, values: &mut S)
where
    S: AsMut<[T]>,
{
    permutation.apply_inv_slice_in_place(values);
}

/// Applying inverse using heapsort which applies destination in-place and in a fixed time
#[allow(clippy::module_name_repetitions, dead_code)]
pub fn apply_inv_inplace<T: Copy + Default>(destination_indices: &mut [usize], values: &mut [T]) {
    /// Precondition: all elements below `start` are in heap order, expect `start` itself
    fn sift_down<T: Copy + Default>(
        destination_indices: &mut [usize],
        values: &mut [T],
        start: usize,
        end: usize,
    ) {
        let mut root = start;
        loop {
            let mut child = root * 2 + 1; // Get the left child
            if child > end {
                break;
            }
            if child < end && destination_indices[child] < destination_indices[child + 1] {
                // Right child exists and is greater.
                child += 1;
            }
            if destination_indices[root] < destination_indices[child] {
                // If child is greater than root, swap them
                destination_indices.swap(root, child);
                values.swap(root, child);
                root = child;
            } else {
                break;
            }
        }
    }

    // Heapify : This procedure would build a valid max-heap.
    let end = destination_indices.len();
    for start in (0..end / 2).rev() {
        // Skip leaf nodes (end / 2).
        sift_down(destination_indices, values, start, end - 1);
    }
    // Sorting part : Iteratively sift down unsorted part (the heap).
    for end in (1..destination_indices.len()).rev() {
        destination_indices.swap(destination_indices[end], destination_indices[0]);
        values.swap(end, 0);
        sift_down(destination_indices, values, 0, end - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::{apply, apply_inv};
    use permutation::Permutation;

    #[test]
    fn apply_shares() {
        let mut values = ["A", "B", "C", "D"];
        let mut indices = Permutation::from_vec([2, 3, 1, 0]);
        let expected_output_apply = ["C", "D", "B", "A"];
        apply(&mut indices, &mut values);
        assert_eq!(values, expected_output_apply);

        let mut values = ["A", "B", "C", "D"];
        let mut indices = Permutation::from_vec([2, 3, 1, 0]);
        let expected_output_apply_inv = ["D", "C", "A", "B"];
        apply_inv(&mut indices, &mut values);
        assert_eq!(values, expected_output_apply_inv);
    }
}
