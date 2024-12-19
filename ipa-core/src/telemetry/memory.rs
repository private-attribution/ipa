#[cfg(not(jemalloc))]
pub fn periodic_memory_report() { }

#[cfg(jemalloc)]
pub use jemalloc::periodic_memory_report;

#[cfg(jemalloc)]
mod jemalloc {
    use std::sync::LazyLock;

    use tikv_jemalloc_ctl::{epoch_mib, stats::allocated_mib};

    const MB: usize = 2 << 20;

    // In an unfortunate acronym collision, `mib` in the names of the jemalloc
    // statistics stands for "Management Information Base", not "mebibytes".
    // The reporting unit is bytes.

    static EPOCH: LazyLock<epoch_mib> = LazyLock::new(|| {
        tikv_jemalloc_ctl::epoch::mib().unwrap()
    });

    static ALLOCATED: LazyLock<allocated_mib> = LazyLock::new(|| {
        tikv_jemalloc_ctl::stats::allocated::mib().unwrap()
    });

    fn report_memory_usage(count: usize) {
        // Some of the information jemalloc uses when reporting statistics is cached, and
        // refreshed only upon advancing the epoch.
        EPOCH.advance().unwrap();
        let allocated = ALLOCATED.read().unwrap() / MB;
        tracing::debug!("i={count}: {allocated} MiB allocated");
    }

    fn should_print_report(count: usize) -> bool {
        if count == 0 {
            return true;
        }

        let bits = count.ilog2();
        let report_interval_log2 = std::cmp::max(bits.saturating_sub(2), 8);
        let report_interval_mask = (1 << report_interval_log2) - 1;
        (count & report_interval_mask) == 0
    }

    /// Print a memory report periodically, based on the value of `count`.
    ///
    /// As `count` increases, so does the report interval. This results in
    /// a tolerable amount of log messages for loops with many iterations,
    /// while still providing some reporting for shorter loops.
    pub fn periodic_memory_report(count: usize) {
        if should_print_report(count) {
            report_memory_usage(count);
        }
    }
}
