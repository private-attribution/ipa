//! Randomized concurrency tests that use shuttle
//!
use crate::test_fixture::sort::execute_sort;

#[test]
fn sort() {
    // TODO this test is failing, enable running it in GH actions once fixed
    shuttle::check_random(
        || {
            shuttle::future::block_on(execute_sort()).unwrap();
        },
        5,
    );
}
