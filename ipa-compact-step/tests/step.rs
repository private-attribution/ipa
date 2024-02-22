use ipa_compact_step::CompactStep;

#[derive(CompactStep)]
enum AllOptions {
    Simple,
    #[step(name = "simple-named")]
    SimpleNamed,
    #[step(count = 2)]
    Int(u8),
    #[step(count = 3)]
    IntNamed(u16),
    #[step(child = SmallChild)]
    SmallChild,
    #[step(child = SmallChild, name = "sibling")]
    SmallChildNamed,
    #[step(child = SmallChild, count = 3, name = "brood-mate")]
    Brood(i8),
    #[step(child = LargeChild)]
    LargeChild,
}

#[derive(CompactStep)]
enum SmallChild {}

#[derive(CompactStep)]
enum LargeChild {
    #[step(count = 12)]
    Children(u16),
}

#[cfg(test)]
mod tests {
    use ipa_core::protocol::step::CompactStep;

    use crate::AllOptions;

    #[test]
    fn enumerate_options() {
        for i in 0..<AllOptions as CompactStep>::STEP_COUNT {
            println!("{i:02}: {}", <AllOptions as CompactStep>::step_string(i));
        }
    }
}
