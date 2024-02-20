use proc_macro::TokenStream as TokenStreamBasic;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, Data, DataEnum, DeriveInput, Expr,
    Fields, Ident, Lit, MetaNameValue, Token, Type, Variant,
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
#[proc_macro_derive(Step, attributes(step))]
pub fn derive_step(input: TokenStreamBasic) -> TokenStreamBasic {
    let output = match derive_step_impl(parse_macro_input!(input as DeriveInput)) {
        Ok(s) => s,
        Err(e) => e,
    };
    TokenStreamBasic::from(output)
}

fn error<T>(span: Span, msg: &str) -> Result<T, TokenStream> {
    Err(quote_spanned!(span => compile_error!(#msg)))
}

fn derive_step_impl(ast: DeriveInput) -> Result<TokenStream, TokenStream> {
    let name = &ast.ident;
    let Data::Enum(enum_data) = &ast.data else {
        return error(ast.ident.span(), "Step can only be derived for an enum");
    };

    let mut expanded = quote!(
        impl ipa_core::protocol::step::Step for #name {}
    );
    expanded.extend(impl_as_ref(name, enum_data)?);

    Ok(expanded)
}

fn impl_as_ref(ident: &Ident, data: &DataEnum) -> Result<TokenStream, TokenStream> {
    if data.variants.is_empty() {
        let snakey = ident.to_string().to_snake_case();
        return Ok(quote! {
            impl AsRef<str> for #ident {
                fn as_ref(&self) -> &str {
                    #snakey
                }
            }
        });
    }

    let mut name_arrays = Vec::new();
    let mut match_arms = Vec::new();

    for v in &data.variants {
        let ident = &v.ident;
        let StepAttr {
            name: step_name,
            count: step_count,
        } = StepAttr::try_from(v)?;
        if step_count == 1 {
            match_arms.extend(quote! {
                Self::#ident => #step_name,
            });
        } else {
            debug_assert!(step_count > 1);
            let array_name = format_ident!("{}_NAMES", ident.to_string().to_shouting_case());
            let skip_zeros = match step_count - 1 {
                1..=9 => 2,
                10..=99 => 1,
                100..=999 => 0,
                _ => unreachable!(),
            };
            let step_names = (0..step_count)
                .map(|s| step_name.clone() + &format!("{s:03}")[skip_zeros..])
                .collect::<Vec<_>>();
            name_arrays.extend(quote!(
                const #array_name: [&str; #step_count] = [#(#step_names),*];
            ));
            match_arms.extend(quote!(
                Self::#ident(&i) => #array_name[usize::try_from(i).unwrap()],
            ));
        }
    }

    Ok(quote! {
        impl AsRef<str> for #ident {
            fn as_ref(&self) -> &str {
                #(#name_arrays)*
                match self {
                    #(#match_arms)*
                }
            }
        }
    })
}

struct StepAttr {
    name: String,
    count: usize,
}

impl TryFrom<&Variant> for StepAttr {
    type Error = TokenStream;

    fn try_from(variant: &Variant) -> Result<Self, Self::Error> {
        let mut attr = Self {
            name: variant.ident.to_string().to_snake_case(),
            count: 1,
        };

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
                    return Ok(attr);
                };

                if !matches!(&f.ty, Type::Path(_)) {
                    return error(
                        f.ty.span(),
                        "#[derive(Step)] variants need to have a single integer type",
                    );
                }
                // TODO: validate that the type is really an integer.
            }
            Fields::Unit => {}
        }

        let Some(step) = variant.attrs.iter().find(|a| a.path().is_ident("step")) else {
            return Ok(attr);
        };

        for e in step
            .parse_args_with(Punctuated::<MetaNameValue, Token![,]>::parse_terminated)
            .expect("error parsing args on #[step]")
        {
            let Expr::Lit(v) = e.value else {
                return error(
                    e.value.span(),
                    "#[step(...)] only supports literal arguments",
                );
            };
            if e.path.is_ident("max") {
                if matches!(&variant.fields, Fields::Unit) {
                    return error(
                        e.path.span(),
                        "#[step(max = ...)] only applies to integer variants",
                    );
                }
                let Lit::Int(v) = v.lit else {
                    return error(
                        v.lit.span(),
                        "#[step(max = ...))] assignment only supports integer literals",
                    );
                };
                let Ok(v) = v.base10_parse::<usize>() else {
                    return error(v.span(), "#[step(max = ...) invalid value");
                };
                if v >= 1000 {
                    return error(v.span(), "#[step(max = ...)] cannot exceed 1000");
                }
                attr.count = v;
            } else if e.path.is_ident("name") {
                let Lit::Str(v) = v.lit else {
                    return error(
                        v.span(),
                        "#[step(name = ...)] assignment only supports string literals",
                    );
                };
                attr.name = v.value();
            } else {
                return error(e.path.span(), "#[step(...)] unsupported argument");
            }
        }
        Ok(attr)
    }
}

#[cfg(test)]
mod test {
    use proc_macro2::TokenStream;
    use quote::quote;
    use syn::DeriveInput;

    use super::derive_step_impl;

    fn derive(input: TokenStream) -> Result<TokenStream, TokenStream> {
        match syn::parse2::<DeriveInput>(input) {
            Ok(di) => derive_step_impl(di),
            Err(e) => Err(e.to_compile_error()),
        }
    }

    fn derive_success(input: TokenStream, output: TokenStream) {
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
            quote! {
                impl ipa_core::protocol::step::Step for EmptyEnum {}

                impl AsRef<str> for EmptyEnum {
                    fn as_ref(&self) -> &str {
                        "empty_enum"
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
            quote! {
                impl ipa_core::protocol::step::Step for OneArm {}

                impl AsRef<str> for OneArm {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Arm => "arm",
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
            quote! {
                impl ipa_core::protocol::step::Step for OneArm {}

                impl AsRef<str> for OneArm {
                    fn as_ref(&self) -> &str {
                        match self {
                            Self::Arm => "a",
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
            quote! {
                impl ipa_core::protocol::step::Step for ManyArms {}

                impl AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["arm0", "arm1", "arm2"];
                        match self {
                            Self::Arm(&i) => ARM_NAMES[usize::try_from(i).unwrap()],
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
            quote! {
                impl ipa_core::protocol::step::Step for ManyArms {}

                impl AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const ARM_NAMES: [&str; 3usize] = ["a0", "a1", "a2"];
                        match self {
                            Self::Arm(&i) => ARM_NAMES[usize::try_from(i).unwrap()],
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn both_arms() {
        derive_success(
            quote! {
                #[derive(Step)]
                enum ManyArms {
                    Empty,
                    #[step(max = 3)]
                    Int(u8),
                }
            },
            quote! {
                impl ipa_core::protocol::step::Step for ManyArms {}

                impl AsRef<str> for ManyArms {
                    fn as_ref(&self) -> &str {
                        const INT_NAMES: [&str; 3usize] = ["int0", "int1", "int2"];
                        match self {
                            Self::Empty => "empty",
                            Self::Int(&i) => INT_NAMES[usize::try_from(i).unwrap()],
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
            "#[step(max = ...))] assignment only supports integer literals",
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
    fn name_very_invalid() {
        derive_failure(
            quote! {
                #[derive(Step)]
                enum Foo {
                    #[step(name = ())]
                    Bar(u8),
                }
            },
            "#[step(...)] only supports literal arguments",
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
            "#[step(name = ...)] assignment only supports string literals",
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
