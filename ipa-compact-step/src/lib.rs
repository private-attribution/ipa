use std::ops::Add;

use proc_macro::TokenStream as TokenStreamBasic;
use proc_macro2::{Literal, Punct, Spacing, Span, TokenStream};
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, Attribute, Data, DataEnum,
    DeriveInput, Expr, ExprPath, Fields, Ident, Lit, MetaNameValue, Token, Type, Variant,
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

/// # Panics
/// This won't work in a bunch of ways.
/// * The derive attribute needs to be used on a enum.
#[proc_macro_derive(CompactStep, attributes(step))]
pub fn derive_step(input: TokenStreamBasic) -> TokenStreamBasic {
    let output = match derive_step_impl(&parse_macro_input!(input as DeriveInput)) {
        Ok(s) => s,
        Err(e) => e,
    };
    TokenStreamBasic::from(output)
}

fn error<T>(span: Span, msg: &str) -> Result<T, TokenStream> {
    Err(quote_spanned!(span => compile_error!(#msg)))
}

fn derive_step_impl(ast: &DeriveInput) -> Result<TokenStream, TokenStream> {
    let ident = &ast.ident;
    let Data::Enum(data) = &ast.data else {
        return error(ast.ident.span(), "Step can only be derived for an enum");
    };

    let variants = VariantAttr::parse_attrs(data)?;

    Ok(generate(ident, &variants))
}

struct VariantAttrParser<'a> {
    ident: &'a Ident,
    name: Option<String>,
    count: Option<usize>,
    child: Option<ExprPath>,
    integer: bool,
}

impl<'a> VariantAttrParser<'a> {
    fn new(ident: &'a Ident) -> Self {
        Self {
            ident,
            name: None,
            count: None,
            child: None,
            integer: false,
        }
    }

    fn parse(mut self, variant: &Variant) -> Result<VariantAttr, TokenStream> {
        match &variant.fields {
            Fields::Named(_) => {
                return error(
                    variant.fields.span(),
                    "named fields are not supported for #[derive(Step)]",
                )
            }
            Fields::Unnamed(f) => {
                if f.unnamed.len() != 1 {
                    return error(
                        f.span(),
                        "#[derive(Step) only supports empty or integer variants",
                    );
                }
                let Some(f) = f.unnamed.first() else {
                    return Ok(VariantAttr::from(self));
                };

                if !matches!(&f.ty, Type::Path(_)) {
                    return error(
                        f.ty.span(),
                        "#[derive(Step)] variants need to have a single integer type",
                    );
                }
                self.integer = true;
                // Note: it looks like validating that the target type is an integer is
                // close to impossible, so we'll leave things in this state.
                // We use `TryFrom` for the value, so that will fail at least catch
                // any errors.  The only problem being that the errors will be inscrutable.
            }
            Fields::Unit => {}
        }

        let Some(attrs) = variant.attrs.iter().find(|a| a.path().is_ident("step")) else {
            return Ok(VariantAttr::from(self));
        };

        self.parse_attr(attrs)?;
        Ok(VariantAttr::from(self))
    }

    fn parse_attr(&mut self, attrs: &Attribute) -> Result<(), TokenStream> {
        for e in attrs
            .parse_args_with(Punctuated::<MetaNameValue, Token![,]>::parse_terminated)
            .expect("error parsing args on #[step]")
        {
            if e.path.is_ident("max") {
                self.parse_count(e)?;
            } else if e.path.is_ident("name") {
                self.parse_name(e)?;
            } else if e.path.is_ident("child") {
                self.parse_child(e)?;
            } else {
                return error(e.path.span(), "#[step(...)] unsupported argument");
            }
        }
        Ok(())
    }

    fn parse_count(&mut self, e: MetaNameValue) -> Result<(), TokenStream> {
        if self.count.is_some() {
            return error(e.span(), "#[step(max = ...)] duplicated");
        }
        if self.child.is_some() {
            return error(
                e.span(),
                "#[step(child = ...)] and #[step(max = ...)] are mutually exclusive",
            );
        }

        let Expr::Lit(v) = &e.value else {
            return error(
                e.value.span(),
                "#[step(max = ...)] only supports literal arguments",
            );
        };
        if !self.integer {
            return error(
                e.path.span(),
                "#[step(max = ...)] only applies to integer variants",
            );
        }
        let Lit::Int(v) = &v.lit else {
            return error(
                v.lit.span(),
                "#[step(max = ...))] only supports integer literals",
            );
        };
        let Ok(v) = v.base10_parse::<usize>() else {
            return error(v.span(), "#[step(max = ...) invalid value");
        };

        if v >= 1000 {
            return error(v.span(), "#[step(max = ...)] cannot exceed 1000");
        }

        self.count = Some(v);
        Ok(())
    }

    fn parse_name(&mut self, e: MetaNameValue) -> Result<(), TokenStream> {
        if self.name.is_some() {
            return error(e.span(), "#[step(name = ...)] duplicated");
        }

        let Expr::Lit(v) = &e.value else {
            return error(
                e.value.span(),
                "#[step(name = ...)] only supports literal arguments",
            );
        };
        let Lit::Str(v) = &v.lit else {
            return error(
                v.span(),
                "#[step(name = ...)] only supports string literals",
            );
        };

        self.name = Some(v.value());
        Ok(())
    }

    fn parse_child(&mut self, e: MetaNameValue) -> Result<(), TokenStream> {
        if self.child.is_some() {
            return error(e.span(), "#[step(child = ...)] duplicated");
        }
        if self.count.is_some() {
            return error(
                e.span(),
                "#[step(child = ...)] and #[step(max = ...)] are mutually exclusive",
            );
        }

        let Expr::Path(p) = &e.value else {
            return error(
                e.value.span(),
                "#[step(child = ...)] needs to specify a type",
            );
        };

        self.child = Some(p.clone());
        Ok(())
    }
}

struct VariantAttr {
    ident: Ident,
    name: String,
    count: usize,
    child: Option<ExprPath>,
}

impl VariantAttr {
    fn parse_attrs(data: &DataEnum) -> Result<Vec<Self>, TokenStream> {
        let mut steps = Vec::with_capacity(data.variants.len());
        for v in &data.variants {
            steps.push(VariantAttrParser::new(&v.ident).parse(v)?);
        }
        Ok(steps)
    }
}

impl From<VariantAttrParser<'_>> for VariantAttr {
    fn from(other: VariantAttrParser) -> Self {
        assert!(
            other.integer ^ other.count.is_none(),
            "cannot have an integer type without a count, or a non-integer type with a count"
        );
        Self {
            ident: other.ident.clone(),
            name: other
                .name
                .unwrap_or_else(|| other.ident.to_string().to_snake_case()),
            count: other.count.unwrap_or(1),
            child: other.child,
        }
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

fn generate(ident: &Ident, variants: &[VariantAttr]) -> TokenStream {
    let mut name_arrays = TokenStream::new();
    let mut as_ref_arms = TokenStream::new();
    let mut arm_count = ExtendedSum::default();
    let mut compact_step_arms = TokenStream::new();

    for VariantAttr {
        ident: step_ident,
        name: step_name,
        count: step_count,
        child: step_child,
    } in variants
    {
        if *step_count == 1 {
            as_ref_arms.extend(quote! {
                Self::#step_ident => #step_name,
            });

            compact_step_arms.extend(quote! {
                #arm_count => Self::#step_ident.as_ref().to_owned(),
            });
            arm_count = arm_count + 1;
            if let Some(child) = step_child {
                let range_end = arm_count.clone()
                    + quote!(<#child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT);
                compact_step_arms.extend(quote! {
                    #arm_count..#range_end => Self::#step_ident.as_ref().to_owned() + '/' +
                      &<#child as ::ipa_core::protocol::step::CompactStep>::step_string(i - (#arm_count)),
                });
                arm_count = range_end;
            }
        } else {
            let array_name = format_ident!("{}_NAMES", step_ident.to_string().to_shouting_case());
            let skip_zeros = match step_count - 1 {
                2..=9 => 2,
                10..=99 => 1,
                100..=999 => 0,
                _ => unreachable!(),
            };
            let step_names = (0..*step_count)
                .map(|s| step_name.clone() + &format!("{s:03}")[skip_zeros..])
                .collect::<Vec<_>>();
            name_arrays.extend(quote! {
                const #array_name: [&str; #step_count] = [#(#step_names),*];
            });
            as_ref_arms.extend(quote! {
                Self::#step_ident(&i) => #array_name[usize::try_from(i).unwrap()],
            });

            let range_end = arm_count.clone() + *step_count;
            compact_step_arms.extend(quote! {
                #arm_count..#range_end => Self::#step_ident(i - (#arm_count)).as_ref().to_owned(),
            });
            arm_count = range_end;
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
                    assert_eq!(i, 0, "step {i} is not valid for {}", ::std::any::type_name::<Self>());
                    Self.as_ref().to_owned()
                }
            }
        });
    } else {
        result.extend(quote! {
            impl ::std::convert::AsRef<str> for #ident {
                fn as_ref(&self) -> &str {
                    #name_arrays
                    match self {
                        #as_ref_arms
                    }
                }
            }

            impl ::ipa_core::protocol::step::CompactStep for #ident {
                const STEP_COUNT: usize = #arm_count;
                fn step_string(i: usize) -> String {
                    match i {
                        #compact_step_arms
                        _ => panic!("step {i} is not valid for {}", ::std::any::type_name::<Self>()),
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
    use syn::DeriveInput;

    use super::derive_step_impl;

    fn derive(input: TokenStream) -> Result<TokenStream, TokenStream> {
        match syn::parse2::<DeriveInput>(input) {
            Ok(di) => derive_step_impl(&di),
            Err(e) => Err(e.to_compile_error()),
        }
    }

    fn derive_success(input: TokenStream, output: &TokenStream) {
        assert_eq!(derive(input).unwrap().to_string(), output.to_string());
    }

    fn derive_failure(input: TokenStream, msg: &str) {
        let expected = quote! { compile_error!(#msg) };
        assert_eq!(derive(input).unwrap_err().to_string(), expected.to_string());
    }

    #[test]
    fn simple() {
        let code = derive(quote! {
                #[derive(Step)]
                enum Simple {
                    Arm,
                    #[step(max = 3)]
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
                #[derive(Step)]
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
                        assert_eq!(i, 0, "step {i} is not valid for {}", ::std::any::type_name::<Self>());
                        Self.as_ref().to_owned()
                    }
                }
            },
        );
    }

    #[test]
    fn one_armed() {
        derive_success(
            quote! {
                #[derive(Step)]
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
                            0usize => Self::Arm.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {}", ::std::any::type_name::<Self>()),
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
                #[derive(Step)]
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
                            0usize => Self::Arm.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {}", ::std::any::type_name::<Self>()),
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn int_arms() {
        derive_success(
            quote! {
                #[derive(Step)]
                enum ManyArms {
                    #[step(max = 3)]
                    Arm(u8),
                }
            },
            &quote! {
                impl ::ipa_core::protocol::step::Step for ManyArms {}

                impl ::std::convert::AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["arm0", "arm1", "arm2"];
                        match self {
                            Self::Arm(&i) => ARM_NAMES[usize::try_from(i).unwrap()],
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for ManyArms {
                    const STEP_COUNT: usize = 3usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            0usize..3usize => Self::Arm(i - (0usize)).as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {}", ::std::any::type_name::<Self>()),
                        }
                    }
                }
            },
        );
    }
    #[test]
    fn int_arms_named() {
        derive_success(
            quote! {
                #[derive(Step)]
                enum ManyArms {
                    #[step(max = 3, name = "a")]
                    Arm(u8),
                }
            },
            &quote! {
                impl ::ipa_core::protocol::step::Step for ManyArms {}

                impl ::std::convert::AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["a0", "a1", "a2"];
                        match self {
                            Self::Arm(&i) => ARM_NAMES[usize::try_from(i).unwrap()],
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for ManyArms {
                    const STEP_COUNT: usize = 3usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            0usize..3usize => Self::Arm(i - (0usize)).as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {}", ::std::any::type_name::<Self>()),
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
                #[derive(Step)]
                enum AllArms {
                    Empty,
                    #[step(max = 3)]
                    Int(u8),
                    #[step(child = ::some::other::StepEnum)]
                    Child,
                    Final,
                }
            },
            &quote! {
                impl ::ipa_core::protocol::step::Step for AllArms {}

                impl ::std::convert::AsRef<str> for AllArms {
                    fn as_ref(&self) -> &str {
                        const INT_NAMES: [&str; 3usize] = ["int0", "int1", "int2"];
                        match self {
                            Self::Empty => "empty",
                            Self::Int(&i) => INT_NAMES[usize::try_from(i).unwrap()],
                            Self::Child => "child",
                            Self::Final => "final",
                        }
                    }
                }

                impl ::ipa_core::protocol::step::CompactStep for AllArms {
                    const STEP_COUNT: usize = <::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 6usize;
                    fn step_string(i: usize) -> String {
                        match i {
                            0usize => Self::Empty.as_ref().to_owned(),
                            1usize..4usize => Self::Int(i - (1usize)).as_ref().to_owned(),
                            4usize => Self::Child.as_ref().to_owned(),
                            5usize..<::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 5usize
                                => Self::Child.as_ref().to_owned() + '/' + &<::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::step_string(i - (5usize)),
                            <::some::other::StepEnum as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 5usize
                                => Self::Final.as_ref().to_owned(),
                            _ => panic!("step {i} is not valid for {}", ::std::any::type_name::<Self>()),
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
                #[derive(Step)]
                struct Foo(u8);
            },
            "Step can only be derived for an enum",
        );
    }

    #[test]
    fn named_variant() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    Named {
                        n: u8,
                    }
                }
            },
            "named fields are not supported for #[derive(Step)]",
        );
    }

    #[test]
    fn empty_variant() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    Bar(),
                }
            },
            "#[derive(Step) only supports empty or integer variants",
        );
    }

    #[test]
    fn tuple_variant() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    Bar((), u8),
                }
            },
            "#[derive(Step) only supports empty or integer variants",
        );
    }

    #[test]
    fn empty_tuple_variant() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    Bar(()),
                }
            },
            "#[derive(Step)] variants need to have a single integer type",
        );
    }

    #[test]
    fn max_unit() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(max = 10)]
                    Bar,
                }
            },
            "#[step(max = ...)] only applies to integer variants",
        );
    }

    #[test]
    fn max_str() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(max = "10")]
                    Bar(u8),
                }
            },
            "#[step(max = ...))] only supports integer literals",
        );
    }

    #[test]
    fn max_too_large() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(max = 10_000)]
                    Bar(u8),
                }
            },
            "#[step(max = ...)] cannot exceed 1000",
        );
    }

    #[test]
    fn two_max() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(max = 1, max = 2)]
                    Bar(u8),
                }
            },
            "#[step(max = ...)] duplicated",
        );
    }

    #[test]
    fn two_names() {
        derive_failure(
            quote! {
                #[derive(Step)]
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
                #[derive(Step)]
                enum Foo {
                    #[step(name = ())]
                    Bar(u8),
                }
            },
            "#[step(name = ...)] only supports literal arguments",
        );
    }

    #[test]
    fn name_invalid() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(name = 12)]
                    Bar(u8),
                }
            },
            "#[step(name = ...)] only supports string literals",
        );
    }

    #[test]
    fn unsupported_argument() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(baz = 12)]
                    Bar(u8),
                }
            },
            "#[step(...)] unsupported argument",
        );
    }
}
