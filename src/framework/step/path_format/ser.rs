#![cfg(feature = "enable-serde")]

use crate::framework::step::path_format::Error;
use serde::{ser, Serialize};

pub fn to_string<T: ?Sized + Serialize>(value: &T) -> Result<String, Error> {
    let mut ser = PathSerializer::new();
    value.serialize(&mut ser)?;
    Ok(ser.output)
}

/// code taken liberally from serde documentation: https://serde.rs/impl-serializer.html
pub struct PathSerializer {
    output: String,
}

impl PathSerializer {
    pub fn new() -> Self {
        PathSerializer {
            output: String::new(),
        }
    }
}

/// supported serialization:
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
impl<'a> ser::Serializer for &'a mut PathSerializer {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    /// put true/false in the path
    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.output += if v { "true" } else { "false" };
        Ok(())
    }

    // all numbers should just have to_string representations in the path

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.output += &v.to_string();
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.output += &v.to_string();
        Ok(())
    }

    /// treat char as single-length string
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(&v.to_string())
    }

    /// just append string to path
    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.output += v;
        Ok(())
    }

    /// for unit structs, put name in path
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(name)
    }

    /// for unit variants in enums, ignore the name and index of the enum;
    /// just serialize the variant's name
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(variant)
    }

    /// if it's a newtype, just treat it as underlying value
    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    /// For a given newtype variant:
    /// enum Example {
    ///     Ex0(String),
    /// }
    /// and instance:
    /// let ex = Example::Ex0("asdf")
    /// serialized format should look like:
    /// ex0/asdf
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        self.output += variant;
        self.output += "/";
        value.serialize(&mut *self)?;
        Ok(())
    }

    /// given a struct:
    /// struct Example(String, i32)
    /// and instance:
    /// let ex = Example("asdf", 4)
    /// serialized format should look like:
    /// example:asdf,4
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.output += name;
        self.output += ":";
        Ok(self)
    }

    /// given a tuple variant:
    /// enum Example {
    ///     Ex1(String, i32)
    /// }
    /// and instance:
    /// let ex = Example::Ex1("asdf", 4)
    /// serialized format should look like:
    /// ex1:asdf,4
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.output += variant;
        self.output += ":";
        Ok(self)
    }

    /// given a struct variant:
    /// enum Example {
    ///     Ex2 {
    ///         str: String,
    ///         num: i32,
    ///     },
    /// }
    /// with instance:
    /// let ex2 = Example::Ex2 {
    ///     str: "asdf",
    ///     num: 4,
    /// }
    /// serialized format should look like:
    /// ex2:str:asdf,num:4
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.output += variant;
        self.output += ":";
        Ok(self)
    }

    // below this point, everything is not supported

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        unimplemented!("floats are not supported")
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        unimplemented!("floats are not supported")
    }

    /// bytes should not be included in path
    fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize bytes")
    }

    /// should never try to serialize nothing
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize unit")
    }

    /// should never try to serialize None
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize None")
    }

    /// should never try to serialize Some
    fn serialize_some<T>(self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!("cannot serialize Some")
    }

    /// disallow seq
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        unimplemented!("cannot serialize seq")
    }

    /// tuples act just like seq; disallow
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        unimplemented!("cannot serialize tuple")
    }

    /// disallow maps
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        unimplemented!("cannot serialize map")
    }

    /// disallow structs
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        unimplemented!("cannot serialize struct")
    }
}

/// given a struct:
/// struct Example(String, i32)
/// and instance:
/// let ex = Example("asdf", 4)
/// serialized format should look like:
/// example:asdf,4
impl<'a> ser::SerializeTupleStruct for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + ser::Serialize,
    {
        // if not the first field
        if !self.output.ends_with(":") {
            self.output += ",";
        }
        value.serialize(&mut **self)?;
        Ok(())
    }

    /// nothing to do at end
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

/// given a tuple variant:
/// enum Example {
///     Ex1(String, i32)
/// }
/// and instance:
/// let ex = Example::Ex1("asdf", 4)
/// serialized format should look like:
/// ex1:asdf,4
impl<'a> ser::SerializeTupleVariant for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + ser::Serialize,
    {
        // if not the first field
        if !self.output.ends_with(":") {
            self.output += ",";
        }
        value.serialize(&mut **self)?;
        Ok(())
    }

    /// nothing to do at end
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

/// given a struct variant:
/// enum Example {
///     Ex2 {
///         str: String,
///         num: i32,
///     },
/// }
/// with instance:
/// let ex2 = Example::Ex2 {
///     str: "asdf",
///     num: 4,
/// }
/// serialized format should look like:
/// ex2:str:asdf,num:4
impl<'a> ser::SerializeStructVariant for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        // if not first field
        if !self.output.ends_with(":") {
            self.output += ",";
        }

        self.output += key;
        self.output += ":";
        value.serialize(&mut **self)?;
        Ok(())
    }

    /// nothing to do at the end
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// below containers are not supported

/// disallow seq
impl<'a> ser::SerializeSeq for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!("cannot serialize seq")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize seq")
    }
}

/// disallow tuple
impl<'a> ser::SerializeTuple for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!("cannot serialize tuple")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize tuple")
    }
}

/// disallow maps
impl<'a> ser::SerializeMap for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_key<T>(&mut self, _key: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!("cannot serialize maps")
    }

    fn serialize_value<T>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + ser::Serialize,
    {
        unimplemented!("cannot serialize maps")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize maps")
    }
}

/// disallow structs
impl<'a> ser::SerializeStruct for &'a mut PathSerializer {
    type Ok = <&'a mut PathSerializer as ser::Serializer>::Ok;
    type Error = <&'a mut PathSerializer as ser::Serializer>::Error;

    fn serialize_field<T>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!("cannot serialize structs")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("cannot serialize structs")
    }
}
