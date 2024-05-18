use ipa_step_derive::CompactStep;

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
    GrandChildren(u16),
    #[step(child = SmallChild)]
    Baby,
}

#[cfg(test)]
mod tests {
    use ipa_step::CompactStep;

    use crate::AllOptions;

    #[test]
    fn enumerate() {
        for i in 0..<AllOptions as CompactStep>::STEP_COUNT {
            let n = <AllOptions as CompactStep>::step_string(i);
            let t = <AllOptions as CompactStep>::step_narrow_type(i).unwrap_or("!");
            println!("{i:02}: {n} -> {t}");
        }
    }
}
