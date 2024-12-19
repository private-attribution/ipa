pub fn periodic_memory_report(count: usize) {
    #[cfg(not(jemalloc))]
    let _ = count;

    #[cfg(jemalloc)]
    jemalloc::periodic_memory_report(count);
}

#[cfg(jemalloc)]
pub mod jemalloc {
    use std::sync::RwLock;

    use tikv_jemalloc_ctl::{epoch_mib, stats::allocated_mib};

    const MB: usize = 2 << 20;

    // In an unfortunate acronym collision, `mib` in the names of the jemalloc
    // statistics stands for "Management Information Base", not "mebibytes".
    // The reporting unit is bytes.

    struct JemallocControls {
        epoch: epoch_mib,
        allocated: allocated_mib,
    }

    static CONTROLS: RwLock<Option<JemallocControls>> = RwLock::new(None);

    /// Activates periodic memory usage reporting during `seq_join`.
    ///
    /// # Panics
    /// If `RwLock` is poisoned.
    pub fn activate() {
        let mut controls = CONTROLS.write().unwrap();

        let epoch = tikv_jemalloc_ctl::epoch::mib().unwrap();
        let allocated = tikv_jemalloc_ctl::stats::allocated::mib().unwrap();

        *controls = Some(JemallocControls { epoch, allocated });
    }

    fn report_memory_usage(controls: &JemallocControls, count: usize) {
        // Some of the information jemalloc uses when reporting statistics is cached, and
        // refreshed only upon advancing the epoch.
        controls.epoch.advance().unwrap();
        let allocated = controls.allocated.read().unwrap() / MB;
        tracing::debug!("i={count}: {allocated} MiB allocated");
    }

    fn should_print_report(count: usize) -> bool {
        if count == 0 {
            return true;
        }

        let bits = count.ilog2();
        let report_interval_log2 = std::cmp::max(bits.saturating_sub(1), 8);
        let report_interval_mask = (1 << report_interval_log2) - 1;
        (count & report_interval_mask) == 0
    }

    /// Print a memory report periodically, based on the value of `count`.
    ///
    /// As `count` increases, so does the report interval. This results in
    /// a tolerable amount of log messages for loops with many iterations,
    /// while still providing some reporting for shorter loops.
    ///
    /// # Panics
    /// If `RwLock` is poisoned.
    pub fn periodic_memory_report(count: usize) {
        let controls_opt = CONTROLS.read().unwrap();
        if let Some(controls) = controls_opt.as_ref() {
            if should_print_report(count) {
                report_memory_usage(controls, count);
            }
        }
    }
}
