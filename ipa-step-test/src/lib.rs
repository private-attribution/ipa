mod basic_step;
mod complex_step;
mod module;

#[cfg(test)]
mod tests {
    use ipa_step::StepNarrow;

    use crate::{
        basic_step::BasicStep,
        complex_step::{ComplexGate, ComplexStep},
        module::{
            a::{Alpha, AlphaGate},
            b::Beta,
        },
    };

    #[test]
    fn narrows() {
        assert_eq!(ComplexGate::default().as_ref(), "/");
        assert_eq!(
            ComplexGate::default().narrow(&ComplexStep::One).as_ref(),
            "/one"
        );
        assert_eq!(
            ComplexGate::default().narrow(&ComplexStep::Two(2)).as_ref(),
            "/two2"
        );
        assert_eq!(
            ComplexGate::default()
                .narrow(&ComplexStep::Two(2))
                .narrow(&BasicStep::One)
                .as_ref(),
            "/two2/one"
        );
        assert_eq!(
            ComplexGate::from("/two2/one"),
            ComplexGate::default()
                .narrow(&ComplexStep::Two(2))
                .narrow(&BasicStep::One)
        );
    }

    #[test]
    #[should_panic(expected = "unknown string for ComplexGate: \"/not/a/gate\"")]
    fn bad_string() {
        _ = ComplexGate::from("/not/a/gate");
    }

    /// Attempts to use `narrow()` will not compile if the type is wrong,
    /// but if the starting state is wrong it will panic.
    #[test]
    #[should_panic(expected = "unexpected narrow for ComplexGate(/two2/one) => BasicStep(two)")]
    fn bad_narrow() {
        _ = ComplexGate::from("/two2/one").narrow(&BasicStep::Two);
    }

    /// Attempts to narrow with an out-of-range index should panic
    /// (rather than produce an incorrect output gate).
    #[test]
    #[should_panic(
        expected = "Index out of range in ComplexStep. Consider using bounds-checked step constructors."
    )]
    fn index_out_of_range() {
        _ = ComplexGate::default().narrow(&ComplexStep::Two(10));
    }

    /// Test that the alpha and beta gates work.
    #[test]
    fn alpha_and_beta() {
        assert_eq!(
            AlphaGate::default().narrow(&Alpha).narrow(&Beta::One),
            AlphaGate::from("/alpha/one")
        );
    }
}
