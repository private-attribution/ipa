mod basic_step;
mod complex_step;

#[cfg(test)]
mod tests {
    use ipa_step::StepNarrow;

    use crate::{
        basic_step::BasicStep,
        complex_step::{ComplexGate, ComplexStep},
    };

    #[test]
    fn it_works() {
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
}
