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

#[cfg(disabled)]
mod tmp {
    fn step_narrow_type(i: usize) -> Option<&'static str> {
        match i {
            _ if i == 0usize => Some(::std::any::type_name::<Child>()),
            _ if (1usize..<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1usize).contains(&i) => {
                <Child as ::ipa_step::CompactStep>::step_narrow_type(i - (1usize))
            }
            _ => None,
        }
        assert_eq!(SmallChild.index(), 0);
    }
}
