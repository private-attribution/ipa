#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod sum;
mod variant;

use std::env;

use ipa_step::{
    name::{CaseStyle, GateName},
    COMPACT_GATE_INCLUDE_ENV,
};
use proc_macro::TokenStream as TokenStreamBasic;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Ident};

use crate::{sum::ExtendedSum, variant::VariantAttribute};

/// Derive an implementation of `Step` and `CompactStep`.
///
/// # Panics
/// This can fail in a bunch of ways.
/// * The derive attribute needs to be used on a enum.
/// * Attributes need to be set correctly.
#[proc_macro_derive(CompactStep, attributes(step))]
pub fn derive_step(input: TokenStreamBasic) -> TokenStreamBasic {
    let output = match derive_step_impl(&parse_macro_input!(input as DeriveInput)) {
        Ok(s) => s,
        Err(e) => e.into_compile_error(),
    };
    TokenStreamBasic::from(output)
}

#[proc_macro_derive(CompactGate)]
pub fn derive_gate(input: TokenStreamBasic) -> TokenStreamBasic {
    TokenStreamBasic::from(derive_gate_impl(&parse_macro_input!(input as DeriveInput)))
}

/// A utility trait that allows for more streamlined error reporting.
trait IntoSpan {
    fn into_span(self) -> Result<Span, syn::Error>;

    fn error<T>(self, msg: &str) -> Result<T, syn::Error>
    where
        Self: Sized,
    {
        Err(syn::Error::new(self.into_span()?, msg))
    }
}

impl IntoSpan for Span {
    fn into_span(self) -> Result<Span, syn::Error> {
        Ok(self)
    }
}

impl<T> IntoSpan for &T
where
    T: syn::spanned::Spanned,
{
    fn into_span(self) -> Result<Span, syn::Error> {
        Ok(self.span())
    }
}

fn derive_step_impl(ast: &DeriveInput) -> Result<TokenStream, syn::Error> {
    let ident = &ast.ident;
    let Data::Enum(data) = &ast.data else {
        return ast.ident.error("Step can only be derived for an enum");
    };

    let variants = VariantAttribute::parse_attrs(data)?;
    Ok(generate(ident, &variants))
}

fn generate(ident: &Ident, variants: &[VariantAttribute]) -> TokenStream {
    // This keeps a running tally of the total number of steps across all of the variants.
    // This is a composite because it isn't necessarily a simple integer.
    // It might be `<Child as CompactStep>::STEP_COUNT + 4` or similar.
    let mut arm_count = ExtendedSum::default();
    // This tracks the index of each item.
    let mut index_arms = TokenStream::new();
    // This tracks the arrays of names that are used for integer variants.
    let mut name_arrays = TokenStream::new();
    // This tracks the arms of the `AsRef<str>` match implementation.
    let mut as_ref_arms = TokenStream::new();
    // This tracks the arms of the `CompactStep::step_string` match implementation.
    let mut step_string_arms = TokenStream::new();
    // This tracks the arms of a `CompactStep::step_narrow_type` match implementation.
    let mut step_narrow_arms = TokenStream::new();

    for v in variants {
        arm_count = v.generate(
            &arm_count,
            &mut index_arms,
            &mut name_arrays,
            &mut as_ref_arms,
            &mut step_string_arms,
            &mut step_narrow_arms,
        );
    }

    let mut result = quote! {
        impl ::ipa_step::Step for #ident {}
    };

    // Maybe override the default implementation of `step_narrow_type`.
    let step_narrow = if step_narrow_arms.is_empty() {
        TokenStream::new()
    } else {
        quote! {
            fn step_narrow_type(i: ::ipa_step::CompactGateIndex) -> Option<&'static str> {
                match i {
                    #step_narrow_arms
                    _ => None,
                }
            }
        }
    };

    if as_ref_arms.is_empty() {
        let snakey = ident.to_string().to_snake_case();
        result.extend(quote! {
            impl ::std::convert::AsRef<str> for #ident {
                fn as_ref(&self) -> &str {
                    #snakey
                }
            }

            impl ::ipa_step::CompactStep for #ident {
                const STEP_COUNT: ::ipa_step::CompactGateIndex = 1;
                fn base_index(&self) -> ::ipa_step::CompactGateIndex { 0 }
                fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                    assert_eq!(i, 0, "step {i} is not valid for {t}", t = ::std::any::type_name::<Self>());
                    String::from(#snakey)
                }
                #step_narrow
            }
        });
    } else {
        // Deal with the use of `TryFrom` on types that implement `From`.
        if !name_arrays.is_empty() {
            result.extend(quote! {
                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                )]
            });
        }
        result.extend(quote! {
            impl ::std::convert::AsRef<str> for #ident {
                fn as_ref(&self) -> &str {
                    #name_arrays
                    match self {
                        #as_ref_arms
                    }
                }
            }
        });

        // Implementing `CompactStep` involves some cases where 0 is added or subtracted.
        // In addition to the useless conversions above.
        if !name_arrays.is_empty() {
            result.extend(quote! {
                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                    clippy::identity_op,
                )]
            });
        }
        result.extend(quote! {
            impl ::ipa_step::CompactStep for #ident {
                const STEP_COUNT: ::ipa_step::CompactGateIndex = #arm_count;
                fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                    match self {
                        #index_arms
                    }
                }
                fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                    match i {
                        #step_string_arms
                        _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                    }
                }
                #step_narrow
            }
        });
    };

    result
}

fn derive_gate_impl(ast: &DeriveInput) -> TokenStream {
    let step = ast.ident.to_string();
    let gate_name = GateName::new(&step);
    let name = Ident::new(&gate_name.name(), Span::call_site());

    let mut result = quote! {
        /// A compact `Gate` corresponding to #step.
        ///
        /// Note that the ordering of this gate implementation might not match
        /// the ordering of [`Descriptive`].
        ///
        /// [`Descriptive`]: crate::descriptive::Descriptive
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct #name(::ipa_step::CompactGateIndex);
        impl ::ipa_step::Gate for #name {}
        impl ::std::default::Default for #name {
            fn default() -> Self {
                Self(0)
            }
        }

        impl ::std::fmt::Display for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_ref())
            }
        }
        impl ::std::fmt::Debug for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str("gate=")?;
                <Self as ::std::fmt::Display>::fmt(self, f)
            }
        }
    };

    // This environment variable is set by build scripts,
    // and is then available (only) during the main build.
    if env::var(COMPACT_GATE_INCLUDE_ENV).is_ok() {
        let filename = gate_name.filename();
        result.extend(quote! {
            include!(concat!(env!("OUT_DIR"), "/", #filename));
        });
    } else {
        result.extend(quote! {
        impl ::std::convert::AsRef<str> for #name {
            fn as_ref(&self) -> &str {
                unimplemented!()
            }
        }

        impl ::std::convert::From<&str> for #name {
            fn from(s: &str) -> Self {
                unimplemented!()
            }
        }
        });
    }

    result
}

#[cfg(test)]
mod test {
    use proc_macro2::TokenStream;
    use quote::quote;

    use super::derive_step_impl;

    fn derive(input: TokenStream) -> Result<TokenStream, TokenStream> {
        match syn::parse2::<syn::DeriveInput>(input) {
            Ok(di) => derive_step_impl(&di),
            Err(e) => Err(e),
        }
        .map_err(syn::Error::into_compile_error)
    }

    fn derive_success(input: TokenStream, output: &TokenStream) {
        assert_eq!(derive(input).unwrap().to_string(), output.to_string());
    }

    fn derive_failure(input: TokenStream, msg: &str) {
        let expected = quote! { ::core::compile_error!{ #msg } };
        assert_eq!(derive(input).unwrap_err().to_string(), expected.to_string());
    }

    #[test]
    fn simple() {
        let code = derive(quote! {
            #[derive(CompactStep)]
            enum Simple {
                Arm,
                #[step(count = 3)]
                Leg(usize),
            }
        })
        .unwrap();

        println!("{code}");
        assert!(syn::parse2::<syn::File>(code).is_ok());
    }

    #[test]
    fn empty() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum EmptyEnum {}
            },
            &quote! {
                impl ::ipa_step::Step for EmptyEnum {}

                impl ::std::convert::AsRef<str> for EmptyEnum {
                    fn as_ref(&self) -> &str {
                        "empty_enum"
                    }
                }

                impl ::ipa_step::CompactStep for EmptyEnum {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = 1;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex { 0 }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        assert_eq!(i, 0, "step {i} is not valid for {t}", t = ::std::any::type_name::<Self>());
                        String::from("empty_enum")
                    }
                }
            },
        );
    }

    #[test]
    fn one_armed() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum OneArm {
                    Arm,
                }
            },
            &quote! {
                impl ::ipa_step::Step for OneArm {}

                impl ::std::convert::AsRef<str> for OneArm {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Arm => "arm",
                        }
                    }
                }

                impl ::ipa_step::CompactStep for OneArm {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = 1;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Arm => 0,
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i == 0 => Self::Arm.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn one_armed_named() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum OneArm {
                    #[step(name = "a")]
                    Arm,
                }
            },
            &quote! {
                impl ::ipa_step::Step for OneArm {}

                impl ::std::convert::AsRef<str> for OneArm {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Arm => "a",
                        }
                    }
                }

                impl ::ipa_step::CompactStep for OneArm {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = 1;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Arm => 0,
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i == 0 => Self::Arm.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn int_arm() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum ManyArms {
                    #[step(count = 3)]
                    Arm(u8),
                }
            },
            &quote! {
                impl ::ipa_step::Step for ManyArms {}

                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                )]
                impl ::std::convert::AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3] = ["arm0", "arm1", "arm2"];
                        match self {
                            Self::Arm(i) => ARM_NAMES[::ipa_step::CompactGateIndex::try_from(*i).unwrap()],
                        }
                    }
                }

                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                    clippy::identity_op,
                )]
                impl ::ipa_step::CompactStep for ManyArms {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = 3;
                    fn base_index (& self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Arm (i) => ::ipa_step::CompactGateIndex::try_from(*i).unwrap(),
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i < 3 => Self::Arm(u8::try_from(i - (0)).unwrap()).as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn int_arm_named() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum ManyArms {
                    #[step(count = 3, name = "a")]
                    Arm(u8),
                }
            },
            &quote! {
                impl ::ipa_step::Step for ManyArms {}

                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                )]
                impl ::std::convert::AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3] = ["a0", "a1", "a2"];
                        match self {
                            Self::Arm(i) => ARM_NAMES[::ipa_step::CompactGateIndex::try_from(*i).unwrap()],
                        }
                    }
                }

                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                    clippy::identity_op,
                )]
                impl ::ipa_step::CompactStep for ManyArms {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = 3;
                    fn base_index (& self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Arm (i) => ::ipa_step::CompactGateIndex::try_from(*i).unwrap(),
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i < 3 => Self::Arm(u8::try_from(i - (0)).unwrap()).as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn child_arm() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum Parent {
                    #[step(child = Child)]
                    Offspring,
                }
            },
            &quote! {
                impl ::ipa_step::Step for Parent {}

                impl ::std::convert::AsRef<str> for Parent {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Offspring => "offspring",
                        }
                    }
                }

                impl ::ipa_step::CompactStep for Parent {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Offspring => 0,
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i == 0 => Self::Offspring.as_ref().to_owned(),
                            _ if i < <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1
                                => Self::Offspring.as_ref().to_owned() + "/" + &<Child as ::ipa_step::CompactStep>::step_string(i - (1)),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }

                    fn step_narrow_type(i: ::ipa_step::CompactGateIndex) -> Option<&'static str> {
                        match i {
                            _ if i == 0 => Some(::std::any::type_name::<Child>()),
                            _ if (1..<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1).contains(&i)
                              => <Child as ::ipa_step::CompactStep>::step_narrow_type(i - (1)),
                            _ => None,
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn child_arm_named() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum Parent {
                    #[step(child = Child, name = "spawn")]
                    Offspring,
                }
            },
            &quote! {
                impl ::ipa_step::Step for Parent {}

                impl ::std::convert::AsRef<str> for Parent {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Offspring => "spawn",
                        }
                    }
                }

                impl ::ipa_step::CompactStep for Parent {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Offspring => 0,
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i == 0 => Self::Offspring.as_ref().to_owned(),
                            _ if i < <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1
                                => Self::Offspring.as_ref().to_owned() + "/" + &<Child as ::ipa_step::CompactStep>::step_string(i - (1)),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }

                    fn step_narrow_type(i: ::ipa_step::CompactGateIndex) -> Option<&'static str> {
                        match i {
                            _ if i == 0 => Some(::std::any::type_name::<Child>()),
                            _ if (1..<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1).contains(&i)
                              => <Child as ::ipa_step::CompactStep>::step_narrow_type(i - (1)),
                            _ => None,
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn int_child() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum Parent {
                    #[step(child = Child, count = 5, name = "spawn")]
                    Offspring(u8),
                }
            },
            &quote! {
                impl ::ipa_step::Step for Parent {}


                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                )]
                impl ::std::convert::AsRef<str> for Parent {
                    fn as_ref(&self) -> &str {
                        const OFFSPRING_NAMES: [&str; 5] =
                            ["spawn0", "spawn1", "spawn2", "spawn3", "spawn4"];
                        match self {
                            Self::Offspring(i) => OFFSPRING_NAMES[::ipa_step::CompactGateIndex::try_from(*i).unwrap()],
                        }
                    }
                }


                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                    clippy::identity_op,
                )]
                impl ::ipa_step::CompactStep for Parent {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = (<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1) * 5;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Offspring(i) => (<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1) * ::ipa_step::CompactGateIndex::try_from(*i).unwrap(),
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i < (<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1) * 5 => {
                                let offset = i - (0);
                                let divisor = <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                                let s = Self::Offspring(u8::try_from(offset / divisor).unwrap())
                                    .as_ref()
                                    .to_owned();
                                if let Some(v) = (offset % divisor).checked_sub(1) {
                                    s + "/" + &<Child as ::ipa_step::CompactStep>::step_string(v)
                                } else {
                                    s
                                }
                            }
                            _ => panic!(
                                "step {i} is not valid for {t}",
                                t = ::std::any::type_name::<Self>()
                            ),
                        }
                    }
                    fn step_narrow_type(i: ::ipa_step::CompactGateIndex) -> Option<&'static str> {
                        match i {
                            _ if (0..(<Child as ::ipa_step::CompactStep>::STEP_COUNT + 1) * 5).contains(&i) => {
                                let offset = i - (0);
                                let divisor = <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                                if let Some(v) = (offset % divisor).checked_sub(1) {
                                    <Child as ::ipa_step::CompactStep>::step_narrow_type(v)
                                } else {
                                    Some(::std::any::type_name::<Child>())
                                }
                            }
                            _ => None,
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn all_arms() {
        derive_success(
            quote! {
                #[derive(CompactStep)]
                enum AllArms {
                    Empty,
                    #[step(count = 3)]
                    Int(usize),
                    #[step(child = ::some::other::StepEnum)]
                    Child,
                    Final,
                }
            },
            &quote! {
                impl ::ipa_step::Step for AllArms {}

                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                )]
                impl ::std::convert::AsRef<str> for AllArms {
                    fn as_ref(&self) -> &str {
                        const INT_NAMES: [&str; 3] = ["int0", "int1", "int2"];
                        match self {
                            Self::Empty => "empty",
                            Self::Int(i) => INT_NAMES[::ipa_step::CompactGateIndex::try_from(*i).unwrap()],
                            Self::Child => "child",
                            Self::Final => "final",
                        }
                    }
                }

                #[allow(
                    clippy::useless_conversion,
                    clippy::unnecessary_fallible_conversions,
                    clippy::identity_op,
                )]
                impl ::ipa_step::CompactStep for AllArms {
                    const STEP_COUNT: ::ipa_step::CompactGateIndex = <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 6;
                    fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                        match self {
                            Self::Empty => 0,
                            Self::Int(i) => ::ipa_step::CompactGateIndex::try_from(*i).unwrap() + 1,
                            Self::Child => 4,
                            Self::Final => <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 5,
                        }
                    }
                    fn step_string(i: ::ipa_step::CompactGateIndex) -> String {
                        match i {
                            _ if i == 0 => Self::Empty.as_ref().to_owned(),
                            _ if i < 4 => Self::Int(usize::try_from(i - (1)).unwrap()).as_ref().to_owned(),
                            _ if i == 4 => Self::Child.as_ref().to_owned(),
                            _ if i < <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 5
                                => Self::Child.as_ref().to_owned() + "/" + &<::some::other::StepEnum as ::ipa_step::CompactStep>::step_string(i - (5)),
                            _ if i == <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 5
                                => Self::Final.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                        }
                    }

                    fn step_narrow_type(i: ::ipa_step::CompactGateIndex) -> Option<&'static str> {
                        match i {
                            _ if i == 4 => Some(::std::any::type_name::<::some::other::StepEnum>()),
                            _ if (5..<::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 5).contains(&i)
                              => <::some::other::StepEnum as ::ipa_step::CompactStep>::step_narrow_type(i - (5)),
                            _ => None,
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn not_enum() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                struct Foo(u8);
            },
            "Step can only be derived for an enum",
        );
    }

    #[test]
    fn named_variant() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    Named {
                        n: u8,
                    }
                }
            },
            "#[derive(CompactStep)] does not support named field",
        );
    }

    #[test]
    fn with_discriminant() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    Bar = 1,
                }
            },
            "#[derive(CompactStep)] does not work with discriminants",
        );
    }

    #[test]
    fn empty_variant() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    Bar(),
                }
            },
            "#[derive(CompactStep) only supports empty or integer variants",
        );
    }

    #[test]
    fn tuple_variant() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    Bar((), u8),
                }
            },
            "#[derive(CompactStep) only supports empty or integer variants",
        );
    }

    #[test]
    fn empty_tuple_variant() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    Bar(()),
                }
            },
            "#[derive(CompactStep)] variants need to have a single integer type",
        );
    }

    #[test]
    fn count_unit() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(count = 10)]
                    Bar,
                }
            },
            "#[step(count = ...)] only applies to integer variants",
        );
    }

    #[test]
    fn count_str() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(count = "10")]
                    Bar(u8),
                }
            },
            "expected integer literal",
        );
    }

    #[test]
    fn count_too_small() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(count = 1)]
                    Bar(u8),
                }
            },
            "#[step(count = ...)] needs to be at least 2 and less than 1000",
        );
    }

    #[test]
    fn count_too_large() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(count = 10_000)]
                    Bar(u8),
                }
            },
            "#[step(count = ...)] needs to be at least 2 and less than 1000",
        );
    }

    #[test]
    fn two_count() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(count = 3, count = 3)]
                    Bar(u8),
                }
            },
            "#[step(count = ...)] duplicated",
        );
    }

    #[test]
    fn two_kids() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(child = Foo, child = Foo)]
                    Bar(u8),
                }
            },
            "#[step(child = ...)] duplicated",
        );
    }

    #[test]
    fn lit_kid() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(child = 3)]
                    Bar(u8),
                }
            },
            "expected identifier",
        );
    }

    #[test]
    fn two_names() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(name = "one", name = "two")]
                    Bar(u8),
                }
            },
            "#[step(name = ...)] duplicated",
        );
    }

    #[test]
    fn name_invalid() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(name = 12)]
                    Bar(u8),
                }
            },
            "expected string literal",
        );
    }

    #[test]
    fn name_slask() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(name = "/")]
                    Bar(u8),
                }
            },
            "#[step(name = ...)] cannot contain '/'",
        );
    }

    #[test]
    fn unsupported_argument() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(baz = 12)]
                    Bar(u8),
                }
            },
            "#[step(...)] unsupported argument",
        );
    }
}
