use embed_doc_image::embed_doc_image;
/// Permutation reorders (1, 2, . . . , m) into (σ(1), σ(2), . . . , σ(m)).
/// For example, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is reordered into (C, D, B, A) by σ.
#[embed_doc_image("apply", "images/sort/apply.png")]
#[allow(dead_code)]
pub fn apply<T: Copy + Default>(source_indices: &[usize], values: &[T]) -> Vec<T> {
    let mut applied_vec: Vec<T> = (0..source_indices.len())
        .map(|_| Default::default())
        .collect();
    (0..source_indices.len()).for_each(|i| {
        let idx = source_indices[i];
        applied_vec[i] = values[idx];
    });
    applied_vec
}

/// To compute `apply_inv` on values, destination_indices(i) can be regarded as the destination of i, i.e., the i-th item
/// is moved by `apply_inv` to be the σ(i)-th item. Therefore, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is
/// reordered into (D, C, A, B).
#[embed_doc_image("apply_inv", "images/sort/apply_inv.png")]
#[allow(clippy::module_name_repetitions, dead_code)]
pub fn apply_inv<T: Copy + Default>(destination_indices: &[usize], values: &[T]) -> Vec<T> {
    let mut applied_vec: Vec<T> = (0..destination_indices.len())
        .map(|_| Default::default())
        .collect();
    (0..destination_indices.len()).for_each(|i| {
        let idx = destination_indices[i];
        applied_vec[idx] = values[i];
    });
    applied_vec
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
    use super::{apply, apply_inv, apply_inv_inplace};

    #[test]
    fn apply_shares() {
        let values = ["A", "B", "C", "D"];
        let indices = [2_usize, 3, 1, 0];
        let expected_output_apply = ["C", "D", "B", "A"];
        let output = apply(&indices, &values);
        assert_eq!(output, expected_output_apply);

        let expected_output_apply_inv = ["D", "C", "A", "B"];
        let output = apply_inv(&indices, &values);
        assert_eq!(output, expected_output_apply_inv);
    }

    #[test]
    fn test_inplace() {
        let mut destination_indices = [2_usize, 3, 1, 0];
        let mut values = ["A", "B", "C", "D"];
        let expected_output = ["D", "C", "A", "B"];
        apply_inv_inplace(&mut destination_indices, &mut values);
        assert_eq!(values, expected_output);
    }
}
