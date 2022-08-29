use crate::framework::step::path_format::Error;
use serde::de::{DeserializeSeed, EnumAccess, SeqAccess, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::ops::{AddAssign, MulAssign, Neg};

pub fn from_str<'a, T>(s: &'a str) -> Result<T, Error>
where
    T: Deserialize<'a>,
{
    let mut deserializer = PathDeserializer::from_str(s);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(Error::TrailingCharacters)
    }
}

pub struct PathDeserializer<'de> {
    input: &'de str,
}

impl<'de> PathDeserializer<'de> {
    pub fn from_str(input: &'de str) -> Self {
        PathDeserializer { input }
    }
}

/// taken liberally from serde documentation: https://serde.rs/impl-deserializer.html
/// supported deserialization:
/// * bool
///     * true => true
///     * false => false
/// * all integers (u*, i*)
///     * 1i* => 1
///     * 1u* => 1
/// * char
///     * 'a' => a
/// * str
///     * "asdf" => asdf
/// * unit structs (assume kebab-case)
///     * struct UnitStruct => unit-struct
/// * tuple structs (assume kebab-case)
///     * struct Tuple("asdf": String, 4: i32) => tuple:asdf,4
/// * enums (assume kebab-case)
///     * given:
///       enum Example {
///         UnitEnum,
///         TupleEnum(String, i32),
///         StructEnum {
///           str_value: String,
///           i32_value: i32,
///         }
///       }
///        * Example::UnitEnum => unit-enum
///        * Example::TupleEnum("asdf", 4) => tuple-enum:asdf,4
///        * Example::StructEnum{ str_value: "asdf", i32_value: 4 } => struct-enum:str-value:asdf,i32_value:4
///
///    * given:
///      enum TopLevel {
///        Embedded(Example)
///      }
///        * TopLevel::Embedded(Example::TupleEnum("asdf", 4)) => embedded/unit-enum:asdf,4
///  
/// * newtype struct (treats it as underlying value)
///     * NewType("asdf": String) => asdf
impl<'de> PathDeserializer<'de> {
    // Look at the first character in the input without consuming it.
    fn peek_char(&mut self) -> Result<char, Error> {
        self.input.chars().next().ok_or(Error::Eof)
    }

    // Consume the first character in the input.
    fn next_char(&mut self) -> Result<char, Error> {
        let ch = self.peek_char()?;
        self.input = &self.input[ch.len_utf8()..];
        Ok(ch)
    }

    fn parse_bool(&mut self) -> Result<bool, Error> {
        if self.input.starts_with("true") {
            self.input = &self.input["true".len()..];
            Ok(true)
        } else if self.input.starts_with("false") {
            self.input = &self.input["false".len()..];
            Ok(false)
        } else {
            Err(Error::Expected("boolean"))
        }
    }

    fn parse_int<T>(&mut self, from_u8: impl Fn(u8) -> T) -> Result<T, Error>
    where
        T: AddAssign<T> + MulAssign<T>,
    {
        let mut int = match self.next_char()? {
            ch @ '0'..='9' => from_u8(ch as u8 - b'0'),
            _ => {
                return Err(Error::Expected("integer"));
            }
        };
        loop {
            match self.input.chars().next() {
                Some(ch @ '0'..='9') => {
                    self.input = &self.input[1..];
                    int *= from_u8(10);
                    int += from_u8(ch as u8 - b'0');
                }
                _ => {
                    return Ok(int);
                }
            }
        }
    }

    fn parse_unsigned<T>(&mut self) -> Result<T, Error>
    where
        T: AddAssign<T> + MulAssign<T> + From<u8>,
    {
        self.parse_int(From::from)
    }

    fn parse_signed<T>(&mut self) -> Result<T, Error>
    where
        T: Neg<Output = T> + AddAssign<T> + MulAssign<T> + From<i8>,
    {
        // we are explicitly removing the `-` before parsing
        let from_u8 = |i: u8| T::from(i as i8);

        // Optional minus sign, delegate to `parse_unsigned`, negate if negative.
        match self.input.chars().next() {
            Some('-') => {
                self.input = &self.input[1..];
                self.parse_int(from_u8).map(Neg::neg)
            }
            _ => self.parse_int(from_u8),
        }
    }

    // Parse a string until the next control character, one of ) : ,
    //
    // Makes no attempt to handle escape sequences. What did you expect? This is
    // example code!
    fn parse_string(&mut self) -> Result<&'de str, Error> {
        let end_idx = self
            .input
            .find(|c| c == ')' || c == ':' || c == ',')
            .unwrap_or(self.input.len());
        let res = &self.input[..end_idx];
        self.input = &self.input[end_idx..];
        Ok(res)
    }
}

impl<'de, 'a> Deserializer<'de> for &'a mut PathDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        // TODO: is this possible?
        unimplemented!("don't think this is possible")
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(self.parse_bool()?)
    }

    // The `parse_signed` function is generic over the integer type `T` so here
    // it is invoked with `T=i8`. The next 8 methods are similar.
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(self.parse_signed()?)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i16(self.parse_signed()?)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.parse_signed()?)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(self.parse_signed()?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.parse_unsigned()?)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u16(self.parse_unsigned()?)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.parse_unsigned()?)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.parse_unsigned()?)
    }

    // Float parsing is stupidly hard.
    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("floats are unsupported")
    }

    // Float parsing is stupidly hard.
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("floats are unsupported")
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let single_len_str = self.parse_string()?;
        (single_len_str.len() == 1)
            .then_some(single_len_str.chars().next().unwrap())
            .ok_or(Error::Syntax)
            .and_then(|c| visitor.visit_char(c))
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.parse_string()?)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.parse_string()? == name {
            visitor.visit_unit()
        } else {
            Err(Error::Expected("named struct"))
        }
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    /// given a struct:
    /// struct Example(String, i32)
    /// and instance:
    /// let ex = Example("asdf", 4)
    /// serialized format should look like:
    /// example:asdf,4
    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.parse_string()? != name {
            return Err(Error::Expected("named struct"));
        }
        if self.next_char()? != ':' {
            return Err(Error::Syntax);
        }
        visitor.visit_seq(CommaSeparated::new(self))
    }

    /// given enums:
    /// enum Example {
    ///     UnitVariant,
    ///     TupleVariant(String, i32)
    ///     StructVariant {
    ///         str_val: String,
    ///         i32_val: i32,
    ///     }
    /// }
    /// enum Embeddable {
    ///     Embedded(Example)
    /// }
    /// Embeddable::Embedded(Example::TupleVariant("asdf", 32)) => embedded(tuple-variant(asdf,32))
    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(Enum::new(self))
        // let variant_name = self.parse_string()?;
        // match self.peek_char() {
        //     // visit a unit variant
        //     Err(Error::Eof) => visitor.visit_enum(variant_name.into_deserializer()),
        //     Ok('(') => {}
        //     Ok(_) => Err(Error::Syntax),
        // }
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    // everything underneath this point are not supported

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("bytes are not supported")
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("byte buffers are not supported")
    }

    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("options are not supported")
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("units are not supported")
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("seqs are not supported")
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("tuples are not supported")
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("maps are not supported")
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!("structs are not supported")
    }
}

struct CommaSeparated<'a, 'de: 'a> {
    de: &'a mut PathDeserializer<'de>,
    first: bool,
}

impl<'a, 'de> CommaSeparated<'a, 'de> {
    fn new(de: &'a mut PathDeserializer<'de>) -> Self {
        CommaSeparated { de, first: true }
    }
}

impl<'a, 'de> SeqAccess<'de> for CommaSeparated<'a, 'de> {
    type Error = <&'a mut PathDeserializer<'de> as Deserializer<'de>>::Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        // any elements left?
        if self.de.peek_char()? == '/' {
            return Ok(None);
        }
        // if not first element, expect and remove comma
        if !self.first && self.de.next_char()? != ',' {
            return Err(Error::Expected("array comma"));
        }
        self.first = false;
        seed.deserialize(&mut *self.de).map(Some)
    }
}

struct Enum<'a, 'de: 'a> {
    de: &'a mut PathDeserializer<'de>,
}

impl<'a, 'de> Enum<'a, 'de> {
    fn new(de: &'a mut PathDeserializer<'de>) -> Self {
        Enum { de }
    }
}

/// given enums:
/// enum Example {
///     UnitVariant,
///     TupleVariant(String, i32)
///     StructVariant {
///         str_val: String,
///         i32_val: i32,
///     }
/// }
/// enum Embeddable {
///     Embedded(Example)
/// }
/// Embeddable::Embedded(Example::TupleVariant("asdf", 32)) => embedded(tuple-variant(asdf,32))
impl<'de, 'a> EnumAccess<'de> for Enum<'a, 'de> {
    type Error = <&'a mut PathDeserializer<'de> as Deserializer<'de>>::Error;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let val = seed.deserialize(&mut *self.de)?;
        (self.de.next_char()? == '(')
            .then_some((val, self))
            .ok_or(Error::Expected("open bracket"))
    }
}

impl<'de, 'a> VariantAccess<'de> for Enum<'a, 'de> {
    type Error = <&'a mut PathDeserializer<'de> as Deserializer<'de>>::Error;

    // TODO: what?
    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self.de)
    }

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.de.deserialize_seq(visitor)
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.de.deserialize_map(visitor)
    }
}
