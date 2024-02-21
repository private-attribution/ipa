use std::ops::Add;

use proc_macro::TokenStream as TokenStreamBasic;
use proc_macro2::{Literal, Punct, Spacing, Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
use syn::{
    meta::ParseNestedMeta, parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum,
    DeriveInput, ExprPath, Fields, Ident, LitInt, LitStr, Type, TypePath, Variant,
};

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

trait IntoSpan {
    fn into_span(self) -> Result<Span, syn::Error>;
}

impl IntoSpan for Span {
    fn into_span(self) -> Result<Span, syn::Error> {
        Ok(self)
    }
}

impl IntoSpan for &'_ ParseNestedMeta<'_> {
    fn into_span(self) -> Result<Span, syn::Error> {
        Ok(self.path.require_ident()?.span())
    }
}

fn error<S: IntoSpan, T>(span: S, msg: &str) -> Result<T, syn::Error> {
    Err(syn::Error::new(span.into_span()?, msg))
}

fn derive_step_impl(ast: &DeriveInput) -> Result<TokenStream, syn::Error> {
    let ident = &ast.ident;
    let Data::Enum(data) = &ast.data else {
        return error(ast.ident.span(), "Step can only be derived for an enum");
    };

    let variants = VariantAttribute::parse_attrs(data)?;
    Ok(generate(ident, &variants))
}

struct VariantAttrParser<'a> {
    ident: &'a Ident,
    name: Option<String>,
    count: Option<usize>,
    child: Option<ExprPath>,
    integer: Option<TypePath>,
}

impl<'a> VariantAttrParser<'a> {
    fn new(ident: &'a Ident) -> Self {
        Self {
            ident,
            name: None,
            count: None,
            child: None,
            integer: None,
        }
    }

    fn parse(mut self, variant: &Variant) -> Result<VariantAttribute, syn::Error> {
        match &variant.fields {
            Fields::Named(_) => {
                return error(
                    variant.fields.span(),
                    "#[derive(CompactStep)] does not support named field",
                );
            }
            Fields::Unnamed(f) => {
                if f.unnamed.len() != 1 {
                    return error(
                        f.span(),
                        "#[derive(CompactStep) only supports empty or integer variants",
                    );
                }
                let Some(f) = f.unnamed.first() else {
                    return self.make_attr();
                };

                let Type::Path(int_type) = &f.ty else {
                    return error(
                        f.ty.span(),
                        "#[derive(CompactStep)] variants need to have a single integer type",
                    );
                };
                self.integer = Some(int_type.clone());

                // Note: it looks like validating that the target type is an integer is
                // close to impossible, so we'll leave things in this state.
                // We use `TryFrom` for the value, so that will fail at least catch
                // any errors.  The only problem being that the errors will be inscrutable.
            }
            Fields::Unit => {}
        }
        if let Some((_, d)) = &variant.discriminant {
            return error(
                d.span(),
                "#[derive(CompactStep)] does not work with discriminants",
            );
        }

        let Some(attr) = variant.attrs.iter().find(|a| a.path().is_ident("step")) else {
            return self.make_attr();
        };

        self.parse_attr(attr)?;
        self.make_attr()
    }

    fn parse_attr(&mut self, attr: &Attribute) -> Result<(), syn::Error> {
        attr.parse_nested_meta(|m| {
            if m.path.is_ident("count") {
                self.parse_count(&m)?;
            } else if m.path.is_ident("name") {
                self.parse_name(&m)?;
            } else if m.path.is_ident("child") {
                self.parse_child(&m)?;
            } else {
                return Err(m.error("#[step(...)] unsupported argument"));
            }
            Ok(())
        })
    }

    fn parse_count(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.count.is_some() {
            return error(m, "#[step(count = ...)] duplicated");
        }
        if self.child.is_some() {
            return error(
                m,
                "#[step(child = ...)] and #[step(count = ...)] are mutually exclusive",
            );
        }
        if self.integer.is_none() {
            return error(m, "#[step(count = ...)] only applies to integer variants");
        }

        let v: LitInt = m.value()?.parse()?;
        let Ok(v) = v.base10_parse::<usize>() else {
            return error(v.span(), "#[step(count = ...) invalid value");
        };

        if !(2..1000).contains(&v) {
            return error(
                v.span(),
                "#[step(count = ...)] needs to be at least 2 and less than 1000",
            );
        }

        self.count = Some(v);
        Ok(())
    }

    fn parse_name(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.name.is_some() {
            return error(m, "#[step(name = ...)] duplicated");
        }

        self.name = Some(m.value()?.parse::<LitStr>()?.value());
        Ok(())
    }

    fn parse_child(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.child.is_some() {
            return error(m, "#[step(child = ...)] duplicated");
        }
        if self.count.is_some() {
            return error(
                m,
                "#[step(child = ...)] and #[step(count = ...)] are mutually exclusive",
            );
        }

        self.child = Some(m.value()?.parse::<ExprPath>()?);
        Ok(())
    }

    fn make_attr(self) -> Result<VariantAttribute, syn::Error> {
        if self.integer.is_some() && self.count.is_none() {
            error(
                self.ident.span(),
                "#[derive(CompactStep)] requires that integer variants include #[step(count = ...)]",
            )
        } else {
            Ok(VariantAttribute {
                ident: self.ident.clone(),
                name: self
                    .name
                    .unwrap_or_else(|| self.ident.to_string().to_snake_case()),
                integer: self.count.zip(self.integer),
                child: self.child,
            })
        }
    }
}

struct VariantAttribute {
    ident: Ident,
    name: String,
    integer: Option<(usize, TypePath)>,
    child: Option<ExprPath>,
}

impl VariantAttribute {
    fn parse_attrs(data: &DataEnum) -> Result<Vec<Self>, syn::Error> {
        let mut steps = Vec::with_capacity(data.variants.len());
        for v in &data.variants {
            steps.push(VariantAttrParser::new(&v.ident).parse(v)?);
        }
        Ok(steps)
    }
}

#[derive(Default, Clone)]
struct ExtendedSum {
    expr: TokenStream,
    extra: usize,
}

impl ToTokens for ExtendedSum {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        if !self.expr.is_empty() {
            tokens.extend(self.expr.clone());
            Punct::new('+', Spacing::Alone).to_tokens(tokens);
        }
        Literal::usize_suffixed(self.extra).to_tokens(tokens);
    }
}

impl Add<usize> for ExtendedSum {
    type Output = Self;
    fn add(self, v: usize) -> Self {
        Self {
            expr: self.expr,
            extra: self.extra + v,
        }
    }
}

impl Add<TokenStream> for ExtendedSum {
    type Output = Self;
    fn add(mut self, v: TokenStream) -> Self {
        if !self.expr.is_empty() {
            Punct::new('+', Spacing::Alone).to_tokens(&mut self.expr);
        }
        self.expr.extend(v);
        Self {
            expr: self.expr,
            extra: self.extra,
        }
    }
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

    for VariantAttribute {
        ident: step_ident,
        name: step_name,
        integer: step_integer,
        child: step_child,
    } in variants
    {
        if let Some((step_count, step_integer)) = step_integer {
            let array_name = format_ident!("{}_NAMES", step_ident.to_string().to_shouting_case());
            let skip_zeros = match *step_count - 1 {
                1..=9 => 2,
                10..=99 => 1,
                100..=999 => 0,
                _ => unreachable!("step count is too damn high {step_count}"),
            };
            let step_names =
                (0..*step_count).map(|s| step_name.clone() + &format!("{s:03}")[skip_zeros..]);
            // .collect::<Vec<_>>();
            name_arrays.extend(quote! {
                const #array_name: [&str; #step_count] = [#(#step_names),*];
            });
            as_ref_arms.extend(quote! {
                Self::#step_ident(i) => #array_name[usize::try_from(*i).unwrap()],
            });

            let range_end = arm_count.clone() + *step_count;
            step_string_arms.extend(quote! {
                _ if i < #range_end => Self::#step_ident(#step_integer::try_from(i - (#arm_count)).unwrap()).as_ref().to_owned(),
            });
            arm_count = range_end;
        } else {
            as_ref_arms.extend(quote! {
                Self::#step_ident => #step_name,
            });

            step_string_arms.extend(quote! {
                _ if i == #arm_count => Self::#step_ident.as_ref().to_owned(),
            });
            arm_count = arm_count + 1;
            if let Some(child) = step_child {
                let range_end = arm_count.clone()
                    + quote!(<#child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT);
                step_string_arms.extend(quote! {
                    _ if i < #range_end => Self::#step_ident.as_ref().to_owned() + "/" +
                      &<#child as ::ipa_core::protocol::step::CompactStep>::step_string(i - (#arm_count)),
                });
                arm_count = range_end;
            }
        }
    }

    let mut result = quote! {
        impl ::ipa_core::protocol::step::Step for #ident {}
    };

    if as_ref_arms.is_empty() {
        let snakey = ident.to_string().to_snake_case();
        result.extend(quote! {
            impl ::std::convert::AsRef<str> for #ident {
                fn as_ref(&self) -> &str {
                    #snakey
                }
            }

            impl ::ipa_core::protocol::step::CompactStep for #ident {
                const STEP_COUNT: usize = 1usize;
                fn step_string(i: usize) -> String {
                    assert_eq!(i, 0, "step {i} is not valid for {t}", t = ::std::any::type_name::<Self>());
                    String::from(#snakey)
                }
            }
        });
    } else {
        // Deal with the use of `TryFrom` on types that implement `From`.
        let suppress_warning = if !name_arrays.is_empty() {
            quote!(#[allow(clippy::unnecessary_fallible_conversions)])
        } else {
            TokenStream::new()
        };

        result.extend(quote! {
            impl ::std::convert::AsRef<str> for #ident {
                #suppress_warning
                fn as_ref(&self) -> &str {
                    #name_arrays
                    match self {
                        #as_ref_arms
                    }
                }
            }

            impl ::ipa_core::protocol::step::CompactStep for #ident {
                const STEP_COUNT: usize = #arm_count;
                #suppress_warning
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
                impl ::ipa_core::protocol::step::Step for EmptyEnum {}

                impl ::std::convert::AsRef<str> for EmptyEnum {
                    fn as_ref(&self) -> &str {
                        "empty_enum"
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for EmptyEnum {
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
                impl ::ipa_core::protocol::step::Step for OneArm {}

                impl ::std::convert::AsRef<str> for OneArm {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Arm => "arm",
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for OneArm {
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
                impl ::ipa_core::protocol::step::Step for OneArm {}

                impl ::std::convert::AsRef<str> for OneArm {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Arm => "a",
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for OneArm {
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
                impl ::ipa_core::protocol::step::Step for ManyArms {}

                impl ::std::convert::AsRef<str> for ManyArms {
                    #[allow(clippy::unnecessary_fallible_conversions)]
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["arm0", "arm1", "arm2"];
                        match self {
                            Self::Arm(i) => ARM_NAMES[usize::try_from(*i).unwrap()],
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for ManyArms {
                    const STEP_COUNT: usize = 3usize;
                    #[allow(clippy::unnecessary_fallible_conversions)]
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
                impl ::ipa_core::protocol::step::Step for ManyArms {}

                impl ::std::convert::AsRef<str> for ManyArms {
                    #[allow(clippy::unnecessary_fallible_conversions)]
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["a0", "a1", "a2"];
                        match self {
                            Self::Arm(i) => ARM_NAMES[usize::try_from(*i).unwrap()],
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for ManyArms {
                    const STEP_COUNT: usize = 3usize;
                    #[allow(clippy::unnecessary_fallible_conversions)]
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
                impl ::ipa_core::protocol::step::Step for Parent {}

                impl ::std::convert::AsRef<str> for Parent {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Offspring => "offspring",
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for Parent {
                    const STEP_COUNT: usize = <Child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 1usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Offspring.as_ref().to_owned(),
                            _ if i < <Child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 1usize
                                => Self::Offspring.as_ref().to_owned() + "/" + &<Child as ::ipa_core::protocol::step::CompactStep>::step_string(i - (1usize)),
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
                impl ::ipa_core::protocol::step::Step for Parent {}

                impl ::std::convert::AsRef<str> for Parent {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Offspring => "spawn",
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for Parent {
                    const STEP_COUNT: usize = <Child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 1usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Offspring.as_ref().to_owned(),
                            _ if i < <Child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 1usize
                                => Self::Offspring.as_ref().to_owned() + "/" + &<Child as ::ipa_core::protocol::step::CompactStep>::step_string(i - (1usize)),
                            _ => panic!("step {i} is not valid for {t}", t = ::std::any::type_name::<Self>()),
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
                impl ::ipa_core::protocol::step::Step for AllArms {}

                impl ::std::convert::AsRef<str> for AllArms {
                    #[allow(clippy::unnecessary_fallible_conversions)]
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

                impl ::ipa_core::protocol::step::CompactStep for AllArms {
                    const STEP_COUNT: usize = <::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 6usize;
                    #[allow(clippy::unnecessary_fallible_conversions)]
                    fn step_string(i: usize) -> String {
                        match i {
                            _ if i == 0usize => Self::Empty.as_ref().to_owned(),
                            _ if i < 4usize => Self::Int(usize::try_from(i - (1usize)).unwrap()).as_ref().to_owned(),
                            _ if i == 4usize => Self::Child.as_ref().to_owned(),
                            _ if i < <::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 5usize
                                => Self::Child.as_ref().to_owned() + "/" + &<::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::step_string(i - (5usize)),
                            _ if i == <::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 5usize
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
    fn name_very_invalid() {
        derive_failure(
            quote! {
                #[derive(CompactStep)]
                enum Foo {
                    #[step(name = ())]
                    Bar(u8),
                }
            },
            "expected string literal",
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
