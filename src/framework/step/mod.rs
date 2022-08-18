use crate::framework::Error;
#[cfg(feature = "enable-serde")]
use serde::{
    de::{Error as SerdeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt::Formatter;

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Example(ExampleCircuit),
    ModulusConversion(ModulusConversionDetails),
}

impl Step {
    #[must_use]
    pub fn to_path(&self) -> String {
        match self {
            Self::Example(circuit) => format!("example/{}", circuit.to_path()),
            Self::ModulusConversion(details) => format!("modulus_conversion/{}", details.to_path()),
        }
    }

    pub fn from_path(path_str: &str) -> Result<Step, Error> {
        let path_str = path_str.strip_prefix('/').unwrap_or(path_str);
        let (step, next) = path_str.split_once('/').ok_or(Error::StepParseError)?;
        match step {
            "example" => Ok(Self::Example(ExampleCircuit::from_path(next)?)),
            "modulus_conversion" => Ok(Self::ModulusConversion(
                ModulusConversionDetails::from_path(next)?,
            )),
            _ => Err(Error::StepParseError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExampleCircuit {
    Mul1(),
    Mul2(),
}

impl ExampleCircuit {
    #[must_use]
    pub fn to_path(&self) -> String {
        match self {
            Self::Mul1() => "mul1".to_string(),
            Self::Mul2() => "mul2".to_string(),
        }
    }

    pub fn from_path(path_str: &str) -> Result<ExampleCircuit, Error> {
        match path_str {
            "mul1" => Ok(ExampleCircuit::Mul1()),
            "mul2" => Ok(ExampleCircuit::Mul2()),
            _ => Err(Error::StepParseError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ModulusConversionDetails {
    Mul1 { bit_num: u32 },
    Mul2 { bit_num: u32 },
}

impl ModulusConversionDetails {
    #[must_use]
    pub fn to_path(&self) -> String {
        match self {
            Self::Mul1 { bit_num } => format!("mul1:{}", bit_num),
            Self::Mul2 { bit_num } => format!("mul2:{}", bit_num),
        }
    }

    pub fn from_path(path_str: &str) -> Result<ModulusConversionDetails, Error> {
        match path_str.split_once(':') {
            Some(("mul1", num_str)) => {
                let num = num_str.parse::<u32>().map_err(|_| Error::StepParseError)?;
                Ok(Self::Mul1 { bit_num: num })
            }
            Some(("mul2", num_str)) => {
                let num = num_str.parse::<u32>().map_err(|_| Error::StepParseError)?;
                Ok(Self::Mul2 { bit_num: num })
            }
            _ => Err(Error::StepParseError),
        }
    }
}

#[cfg(feature = "enable-serde")]
impl Serialize for Step {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_path())
    }
}

#[cfg(feature = "enable-serde")]
impl<'de> Deserialize<'de> for Step {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;
        impl<'de2> Visitor<'de2> for StringVisitor {
            type Value = Step;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a \"/\" separated list of steps")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                println!("visited!");
                Step::from_path(&v).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Step::from_path(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_string(StringVisitor)
    }
}
