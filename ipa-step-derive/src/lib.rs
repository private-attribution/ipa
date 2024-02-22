#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod sum;
mod variant;

use proc_macro::TokenStream as TokenStreamBasic;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Ident};

use crate::{sum::ExtendedSum, variant::VariantAttribute};

/// A utility trait that decorates string-ish things and produces
/// `names_like_this` or `NAMES_LIKE_THIS` from `NamesLikeThis`.
trait CaseStyle {
    fn to_snake_case(&self) -> String {
        self.to_underscore(false)
    }

    fn to_shouting_case(&self) -> String {
        self.to_underscore(true)
    }

    fn to_underscore(&self, upper: bool) -> String;
}

impl<T> CaseStyle for T
where
    T: AsRef<str>,
{
    fn to_underscore(&self, upper: bool) -> String {
        self.as_ref().chars().fold(String::new(), |mut acc, c| {
            if c.is_uppercase() {
                if !acc.is_empty() {
                    acc.push('_');
                }
                acc.push(if upper { c } else { c.to_ascii_lowercase() });
            } else {
                acc.push(if upper { c.to_ascii_uppercase() } else { c });
            }
            acc
        })
    }
}

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
    // This tracks the arrays of names that are used for integer variants.
    let mut name_arrays = TokenStream::new();
    // This tracks the arms of the `AsRef<str>` match implementation.
    let mut as_ref_arms = TokenStream::new();
    // This tracks the arms of the `CompactStep::step_string` match implementation.
    let mut step_string_arms = TokenStream::new();

    for v in variants {
        arm_count = v.generate(
            arm_count,
            &mut name_arrays,
            &mut as_ref_arms,
            &mut step_string_arms,
        );
    }

    let mut result = quote! {
        impl ::ipa_step::Step for #ident {}
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
                const STEP_COUNT: usize = 1usize;
                fn step_string(i: usize) -> String {
                    assert_eq!(i, 0, "step {i} is not valid for {t}", t = ::std::any::type_name::<Self>());
                    String::from(#snakey)
                }
            }
        });
    } else {
        // Deal with the use of `TryFrom` on types that implement `From`.
        if !name_arrays.is_empty() {
            result.extend(quote!(#[allow(clippy::unnecessary_fallible_conversions)]));
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
        if !name_arrays.is_empty() {
            result.extend(
                quote!(#[allow(clippy::unnecessary_fallible_conversions, clippy::identity_op)]),
            );
        }
        result.extend(quote! {
            impl ::ipa_step::CompactStep for #ident {
                const STEP_COUNT: usize = #arm_count;
                fn step_string(i: usize) -> String {
                    match i {
                        #step_string_arms
                        _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
                    }
                }
            }
        });
    };

    result.extend(quote! {});
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
                    const STEP_COUNT: usize = 1usize;
                    fn step_string(i: usize) -> String {
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
                    const STEP_COUNT: usize = 1usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Arm.as_ref().to_owned(),
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
                    const STEP_COUNT: usize = 1usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Arm.as_ref().to_owned(),
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

                #[allow(clippy::unnecessary_fallible_conversions)]
                impl ::std::convert::AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["arm0", "arm1", "arm2"];
                        match self {
                            Self::Arm(i) => ARM_NAMES[usize::try_from(*i).unwrap()],
                        }
                    }
                }

                #[allow(clippy::unnecessary_fallible_conversions, clippy::identity_op)]
                impl ::ipa_step::CompactStep for ManyArms {
                    const STEP_COUNT: usize = 3usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i < 3usize => Self::Arm(u8::try_from(i - (0usize)).unwrap()).as_ref().to_owned(),
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

                #[allow(clippy::unnecessary_fallible_conversions)]
                impl ::std::convert::AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["a0", "a1", "a2"];
                        match self {
                            Self::Arm(i) => ARM_NAMES[usize::try_from(*i).unwrap()],
                        }
                    }
                }

                #[allow(clippy::unnecessary_fallible_conversions, clippy::identity_op)]
                impl ::ipa_step::CompactStep for ManyArms {
                    const STEP_COUNT: usize = 3usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i < 3usize => Self::Arm(u8::try_from(i - (0usize)).unwrap()).as_ref().to_owned(),
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
                    const STEP_COUNT: usize = <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Offspring.as_ref().to_owned(),
                            _ if i < <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1usize
                                => Self::Offspring.as_ref().to_owned() + "/" + &<Child as ::ipa_step::CompactStep>::step_string(i - (1usize)),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
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
                    const STEP_COUNT: usize = <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Offspring.as_ref().to_owned(),
                            _ if i < <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1usize
                                => Self::Offspring.as_ref().to_owned() + "/" + &<Child as ::ipa_step::CompactStep>::step_string(i - (1usize)),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
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

                #[allow(clippy::unnecessary_fallible_conversions)]
                impl ::std::convert::AsRef<str> for Parent {
                    fn as_ref(&self) -> &str {
                        const OFFSPRING_NAMES: [&str; 5usize] =
                            ["spawn0", "spawn1", "spawn2", "spawn3", "spawn4"];
                        match self {
                            Self::Offspring(i) => OFFSPRING_NAMES[usize::try_from(*i).unwrap()],
                        }
                    }
                }

                #[allow(clippy::unnecessary_fallible_conversions, clippy::identity_op)]
                impl ::ipa_step::CompactStep for Parent {
                    const STEP_COUNT: usize =
                        (<Child as ::ipa_step::CompactStep>::STEP_COUNT * 6usize);
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i
                                < (<Child as ::ipa_step::CompactStep>::STEP_COUNT * 6usize)
                                    =>
                            {
                                let offset = i - (0usize);
                                let divisor =
                                    <Child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                                let s = Self::Offspring(u8::try_from(offset / divisor).unwrap())
                                    .as_ref()
                                    .to_owned();
                                if let Some(v) = (offset % divisor).checked_sub(1) {
                                    s + "/"
                                        + &<Child as ::ipa_step::CompactStep>::step_string(v)
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

                #[allow(clippy::unnecessary_fallible_conversions)]
                impl ::std::convert::AsRef<str> for AllArms {
                    fn as_ref(&self) -> &str {
                        const INT_NAMES: [&str; 3usize] = ["int0", "int1", "int2"];
                        match self {
                            Self::Empty => "empty",
                            Self::Int(i) => INT_NAMES[usize::try_from(*i).unwrap()],
                            Self::Child => "child",
                            Self::Final => "final",
                        }
                    }
                }

                #[allow(clippy::unnecessary_fallible_conversions, clippy::identity_op)]
                impl ::ipa_step::CompactStep for AllArms {
                    const STEP_COUNT: usize = <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 6usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Empty.as_ref().to_owned(),
                            _ if i < 4usize => Self::Int(usize::try_from(i - (1usize)).unwrap()).as_ref().to_owned(),
                            _ if i == 4usize => Self::Child.as_ref().to_owned(),
                            _ if i < <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 5usize
                                => Self::Child.as_ref().to_owned() + "/" + &<::some::other::StepEnum as ::ipa_step::CompactStep>::step_string(i - (5usize)),
                            _ if i == <::some::other::StepEnum as ::ipa_step::CompactStep>::STEP_COUNT + 5usize
                                => Self::Final.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
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
