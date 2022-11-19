use raw_ipa::error::BoxError;
use raw_ipa::test_fixture::sort::execute_sort;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), BoxError> {
    execute_sort().await
}
