/// Zip two arrays of size three
#[cfg(all(any(test, feature = "test-fixture"), feature = "in-memory-infra"))]
pub fn zip3<T, U>(a: [T; 3], b: [U; 3]) -> [(T, U); 3] {
    let [a0, a1, a2] = a;
    let [b0, b1, b2] = b;
    [(a0, b0), (a1, b1), (a2, b2)]
}

/// Zip two arrays of size three by reference
#[cfg(all(any(test, feature = "test-fixture"), feature = "in-memory-infra"))]
pub fn zip3_ref<'t, 'u, T, U>(a: &'t [T; 3], b: &'u [U; 3]) -> [(&'t T, &'u U); 3] {
    let [a0, a1, a2] = a.each_ref();
    let [b0, b1, b2] = b.each_ref();
    [(a0, b0), (a1, b1), (a2, b2)]
}
