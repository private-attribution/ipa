use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        unit_test: { all(not(feature = "shuttle"), feature = "in-memory-infra") },
        web_test: { all(not(feature = "shuttle"), feature = "real-world-infra") },
    }
}
