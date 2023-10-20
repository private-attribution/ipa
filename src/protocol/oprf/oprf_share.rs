use std::ops::Add;

use generic_array::GenericArray;
use rand::{distributions::Standard, Rng};
use typenum::Unsigned;

use super::OPRFInputRow;
use crate::{
    ff::{Field, Gf32Bit, Gf40Bit, Gf8Bit, Serializable},
    helpers::{Direction, Message},
};
pub type OprfMK = Gf40Bit;
pub type OprfBK = Gf8Bit;
pub type OprfF = Gf32Bit;

#[derive(Debug, Clone, Copy)]
pub struct OPRFShare {
    pub timestamp: OprfF,
    pub mk: OprfMK,
    pub is_trigger_bit: OprfF,
    pub breakdown_key: OprfBK,
    pub trigger_value: OprfF,
}

impl OPRFShare {
    #[must_use]
    pub fn from_input_row(input_row: &OPRFInputRow, shared_with: Direction) -> Self {
        match shared_with {
            Direction::Left => Self {
                timestamp: input_row.timestamp.as_tuple().1,
                mk: input_row.mk_shares.as_tuple().1,
                is_trigger_bit: input_row.is_trigger_bit.as_tuple().1,
                breakdown_key: input_row.breakdown_key.as_tuple().1,
                trigger_value: input_row.trigger_value.as_tuple().1,
            },

            Direction::Right => Self {
                timestamp: input_row.timestamp.as_tuple().0,
                mk: input_row.mk_shares.as_tuple().0,
                is_trigger_bit: input_row.is_trigger_bit.as_tuple().0,
                breakdown_key: input_row.breakdown_key.as_tuple().0,
                trigger_value: input_row.trigger_value.as_tuple().0,
            },
        }
    }

    #[must_use]
    pub fn to_input_row(self, rhs: Self) -> OPRFInputRow {
        OPRFInputRow {
            timestamp: (self.timestamp, rhs.timestamp).into(),
            mk_shares: (self.mk, rhs.mk).into(),
            is_trigger_bit: (self.is_trigger_bit, rhs.is_trigger_bit).into(),
            breakdown_key: (self.breakdown_key, rhs.breakdown_key).into(),
            trigger_value: (self.trigger_value, rhs.trigger_value).into(),
        }
    }
}

impl rand::prelude::Distribution<OPRFShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> OPRFShare {
        OPRFShare {
            timestamp: OprfF::truncate_from(rng.gen::<u128>()),
            mk: OprfMK::truncate_from(rng.gen::<u128>()),
            is_trigger_bit: OprfF::truncate_from(rng.gen::<u128>()),
            breakdown_key: OprfBK::truncate_from(rng.gen::<u128>()),
            trigger_value: OprfF::truncate_from(rng.gen::<u128>()),
        }
    }
}

impl Add for OPRFShare {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

impl<'a, 'b> Add<&'b OPRFShare> for &'a OPRFShare {
    type Output = OPRFShare;

    fn add(self, rhs: &'b OPRFShare) -> Self::Output {
        Self::Output {
            timestamp: self.timestamp + rhs.timestamp,
            mk: self.mk + rhs.mk,
            is_trigger_bit: self.is_trigger_bit + rhs.is_trigger_bit,
            breakdown_key: self.breakdown_key + rhs.breakdown_key,
            trigger_value: self.trigger_value + rhs.trigger_value,
        }
    }
}

impl Serializable for OPRFShare {
    type Size = <<OprfF as Serializable>::Size as Add<
        <<OprfMK as Serializable>::Size as Add<
            <<OprfF as Serializable>::Size as Add<
                <<OprfBK as Serializable>::Size as Add<<OprfF as Serializable>::Size>>::Output,
            >>::Output,
        >>::Output,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <OprfMK as Serializable>::Size::USIZE;
        let bk_sz = <OprfBK as Serializable>::Size::USIZE;
        let f_sz = <OprfF as Serializable>::Size::USIZE;

        self.timestamp
            .serialize(GenericArray::from_mut_slice(&mut buf[..f_sz]));
        self.mk
            .serialize(GenericArray::from_mut_slice(&mut buf[f_sz..f_sz + mk_sz]));
        self.is_trigger_bit.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mk_sz = <OprfMK as Serializable>::Size::USIZE;
        let bk_sz = <OprfBK as Serializable>::Size::USIZE;
        let f_sz = <OprfF as Serializable>::Size::USIZE;

        let timestamp = OprfF::deserialize(GenericArray::from_slice(&buf[..f_sz]));
        let mk = OprfMK::deserialize(GenericArray::from_slice(&buf[f_sz..f_sz + mk_sz]));
        let is_trigger_bit = OprfF::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        let breakdown_key = OprfBK::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        let trigger_value = OprfF::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
        Self {
            timestamp,
            mk,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        }
    }
}

impl Message for OPRFShare {}
