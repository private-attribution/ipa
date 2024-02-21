use ipa_compact_step::CompactStep;
use ipa_core::protocol::step::CompactStep;

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
    #[step(child = SmallChild, name = "other-child")]
    SmallChildNamed,
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

#[test]
fn enumerate_options() {
    for i in 0..<AllOptions as CompactStep>::STEP_COUNT {
        println!("{i:02}: {}", <AllOptions as CompactStep>::step_string(i));
    }
}
