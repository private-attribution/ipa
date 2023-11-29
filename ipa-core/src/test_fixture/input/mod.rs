use crate::{
    ff::{Field, GaloisField},
    secret_sharing::replicated::semi_honest::AdditiveShare,
};

#[cfg(test)]
pub mod sharing;

// Struct that holds all possible fields of the input to IPA. Used for tests only.
#[derive(Debug)]
pub struct GenericReportShare<F: Field, MK: GaloisField, BK: GaloisField> {
    pub match_key: Option<AdditiveShare<MK>>,
    pub attribution_constraint_id: Option<AdditiveShare<F>>,
    pub timestamp: Option<AdditiveShare<F>>,
    pub is_trigger_report: Option<AdditiveShare<F>>,
    pub breakdown_key: Option<AdditiveShare<BK>>,
    pub trigger_value: AdditiveShare<F>,
    pub helper_bit: Option<AdditiveShare<F>>,
    pub aggregation_bit: Option<AdditiveShare<F>>,
    pub active_bit: Option<AdditiveShare<F>>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GenericReportTestInput<F: Field, MK: GaloisField, BK: GaloisField> {
    pub match_key: Option<MK>,
    pub attribution_constraint_id: Option<F>,
    pub timestamp: Option<F>,
    pub is_trigger_report: Option<F>,
    pub breakdown_key: Option<BK>,
    pub trigger_value: F,
    pub helper_bit: Option<F>,
    pub aggregation_bit: Option<F>,
    pub active_bit: Option<F>,
}

#[macro_export]
macro_rules! ipa_test_input {
    ( { timestamp: $ts:expr, match_key: $mk:expr, is_trigger_report: $itr:expr, breakdown_key: $bk:expr, trigger_value: $tv:expr $(,)? }; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        GenericReportTestInput {
            match_key: Some(<$mk_bit_array as $crate::ff::Field>::truncate_from(u128::try_from($mk).unwrap())),
            attribution_constraint_id: None,
            timestamp: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($ts).unwrap())),
            is_trigger_report: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($itr).unwrap())),
            breakdown_key: Some(<$bk_bit_array as $crate::ff::Field>::truncate_from(u128::try_from($bk).unwrap())),
            trigger_value: <$field as $crate::ff::Field>::truncate_from(u128::try_from($tv).unwrap()),
            helper_bit: None,
            aggregation_bit: None,
            active_bit: None,
        }
    };

    ( [ $({ timestamp: $ts:expr, match_key: $mk:expr, is_trigger_report: $itr:expr, breakdown_key: $bk:expr, trigger_value: $tv:expr $(,)? }),* $(,)? ]; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        vec![
            $(ipa_test_input!({ timestamp: $ts, match_key: $mk, is_trigger_report: $itr, breakdown_key: $bk, trigger_value: $tv }; ($field, $mk_bit_array, $bk_bit_array))),*
        ]
    };
}

#[macro_export]
macro_rules! attribution_window_test_input {
    ( { timestamp: $ts:expr, is_trigger_report: $itr:expr, helper_bit: $hb:expr, breakdown_key: $bk:expr, credit: $cdt:expr $(,)? }; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        GenericReportTestInput {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($ts).unwrap())),
            is_trigger_report: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($itr).unwrap())),
            breakdown_key: Some(<$bk_bit_array as $crate::ff::Field>::truncate_from(u128::try_from($bk).unwrap())),
            trigger_value: <$field as $crate::ff::Field>::truncate_from(u128::try_from($cdt).unwrap()),
            helper_bit: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($hb).unwrap())),
            aggregation_bit: None,
            active_bit: None,
        }
    };

    ( [ $({ timestamp: $ts:expr, is_trigger_report: $itr:expr, helper_bit: $hb:expr, breakdown_key: $bk:expr, credit: $cdt:expr $(,)? }),* $(,)? ]; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        vec![
            $(attribution_window_test_input!({ timestamp: $ts, is_trigger_report: $itr, helper_bit: $hb, breakdown_key: $bk, credit: $cdt }; ($field, $mk_bit_array, $bk_bit_array))),*
        ]
    };
}

#[macro_export]
macro_rules! accumulation_test_input {
    ( { is_trigger_report: $itr:expr, helper_bit: $hb:expr, active_bit: $ab:expr, credit: $cdt:expr $(,)? }; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        GenericReportTestInput {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($itr).unwrap())),
            breakdown_key: None,
            trigger_value: <$field as $crate::ff::Field>::truncate_from(u128::try_from($cdt).unwrap()),
            helper_bit: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($hb).unwrap())),
            aggregation_bit: None,
            active_bit: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($ab).unwrap())),
        }
    };

    ( [ $({ is_trigger_report: $itr:expr, helper_bit: $hb:expr, active_bit: $ab:expr, credit: $cdt:expr $(,)? }),* $(,)? ]; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        vec![
            $(accumulation_test_input!({ is_trigger_report: $itr, helper_bit: $hb, active_bit: $ab, credit: $cdt }; ($field, $mk_bit_array, $bk_bit_array))),*
        ]
    };
}

#[macro_export]
macro_rules! credit_capping_test_input {
    ( { is_trigger_report: $itr:expr, helper_bit: $hb:expr, breakdown_key: $bk:expr, credit: $cdt:expr $(,)? }; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        GenericReportTestInput {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($itr).unwrap())),
            breakdown_key: Some(<$bk_bit_array as $crate::ff::Field>::truncate_from(u128::try_from($bk).unwrap())),
            trigger_value: <$field as $crate::ff::Field>::truncate_from(u128::try_from($cdt).unwrap()),
            helper_bit: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($hb).unwrap())),
            aggregation_bit: None,
            active_bit: None,
        }
    };

    ( [ $({ is_trigger_report: $itr:expr, helper_bit: $hb:expr, breakdown_key: $bk:expr, credit: $cdt:expr $(,)? }),* $(,)? ]; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        vec![
            $(credit_capping_test_input!({ is_trigger_report: $itr, helper_bit: $hb, breakdown_key: $bk, credit: $cdt }; ($field, $mk_bit_array, $bk_bit_array))),*
        ]
    };
}

#[macro_export]
macro_rules! aggregation_test_input {
    ( { helper_bit: $hb:expr, breakdown_key: $bk:expr, credit: $cdt:expr $(,)? }; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        GenericReportTestInput {
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            is_trigger_report: None,
            breakdown_key: Some(<$bk_bit_array as $crate::ff::Field>::truncate_from(u128::try_from($bk).unwrap())),
            trigger_value: <$field as $crate::ff::Field>::truncate_from(u128::try_from($cdt).unwrap()),
            helper_bit: Some(<$field as $crate::ff::Field>::truncate_from(u128::try_from($hb).unwrap())),
            aggregation_bit: None,
            active_bit: None,
        }
    };

    ( [ $({ helper_bit: $hb:expr, breakdown_key: $bk:expr, credit: $cdt:expr $(,)? }),* $(,)? ]; ($field:tt, $mk_bit_array:tt, $bk_bit_array:tt) ) => {
        vec![
            $(aggregation_test_input!({ helper_bit: $hb, breakdown_key: $bk, credit: $cdt }; ($field, $mk_bit_array, $bk_bit_array))),*
        ]
    };
}
