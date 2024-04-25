use futures_util::stream;
use ipa_core::helpers::multiplex;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// This integration test simply checks that stream
/// The reason why it is an integration test is shown here:
/// https://docs.rs/dhat/0.3.3/dhat/index.html#heap-usage-testing
#[test]
fn no_leaks() {
    let _profiler = dhat::Profiler::builder().testing().build();

    let stream_shards = multiplex(stream::empty(), 4);
    let stats = dhat::HeapStats::get();
    // Make sure that something is allocated.
    dhat::assert_ne!(stats.curr_blocks, 0);
    drop(stream_shards);

    let stats = dhat::HeapStats::get();
    // No allocations should remain alive.
    dhat::assert_eq!(stats.curr_blocks, 0);
}
