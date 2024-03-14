// Procedural macro to derive the Step traits.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput};
use proc_macro2::{TokenStream as TokenStream2, Literal};

const MAX_DYNAMIC_STEPS: usize = 1024;

trait CaseStyle {
    fn to_snake_case(&self) -> String;
}

impl CaseStyle for String {
    fn to_snake_case(&self) -> String {
        self.chars().fold(String::new(), |acc, c| {
            if c.is_uppercase() {
                let prefix = if acc.is_empty() { "" } else { "_" };
                acc + prefix + c.to_lowercase().to_string().as_str()
            } else {
                acc + c.to_string().as_str()
            }
        })
    }
}

/// Extend the output token vector with the result of the given expression
/// or immediately return from the function with the error.
macro_rules! extend_or_error {
    ($out:tt, $e:expr) => {
        match $e {
            Ok(item) => $out.extend(item),
            Err(e) => {
                $out.extend(TokenStream2::from(e.to_compile_error()));
                return $out.into();
            }
        }
    };
}

pub fn expand(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let data = match &ast.data {
        syn::Data::Enum(i) => i,
        _ => {
            return TokenStream::from(
                syn::Error::new_spanned(ast, "ipa_macros::Step expects an enum").to_compile_error(),
            );
        }
    };

    // all IPA protocol steps need to implement the `Step` trait
    let ident = &ast.ident;
    let mut out = TokenStream2::new();
    extend_or_error!(out, impl_step(ident, data));

    // implement `Display`
    extend_or_error!(out, impl_display(ident, data));

    out.into()
}

/// Generate string representations for each variant of the enum. This is
/// similar to what `strum` does, but we have special handling for dynamic
/// steps.
fn impl_display(ident: &syn::Ident, data: &syn::DataEnum) -> Result<TokenStream2, syn::Error> {
    let mut const_arrays = Vec::new();
    let mut arms = Vec::new();

    for v in data.variants.iter() {
        let ident = &v.ident;
        let ident_snake_case = ident.to_string().to_snake_case();
        let ident_upper_case = ident_snake_case.to_uppercase();

        if is_dynamic_step(v) {
            let num_steps = match get_dynamic_step_count(v) {
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            // create an array of `num_steps` strings and use the variant index as array index
            let steps = (0..num_steps)
                .map(|i| format!("{}{}", ident_snake_case, i))
                .collect::<Vec<_>>();
            let steps_array_ident = format_ident!("{}_DYNAMIC_STEP", ident_upper_case);
            const_arrays.extend(quote!(
                const #steps_array_ident: [&str; #num_steps] = [#(#steps),*];
            ));
            arms.extend(quote!(
                Self::#ident(i) => #steps_array_ident[usize::try_from(*i).unwrap()],
            ));
        } else {
            // generate a single variant for static steps
            arms.extend(quote!(
                Self::#ident => #ident_snake_case,
            ));
        }
    }

    Ok(quote!(
        impl std::fmt::Display for #ident {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                #(#const_arrays)*
                let id = match self {
                    #(#arms)*
                };
                f.write_str(id)
            }
        }
    ))
}

/// Generate `impl Step`.
fn impl_step(
    ident: &syn::Ident,
    data: &syn::DataEnum,
) -> Result<TokenStream2, syn::Error> {
    let dynamic_step = data
        .variants
        .iter()
        .filter(|v| is_dynamic_step(v))
        .try_fold(None, |prev, item| {
            match prev {
                None => Ok(Some(item)),
                Some(_) => Err(syn::Error::new_spanned(
                    ident,
                    "ipa_macros::step supports no more than one dynamic substep per step",
                )),
            }
        })?;

    let substeps = data.variants.len() + dynamic_step.map_or(Ok(0), |d| get_dynamic_step_count(d).map(|n| n - 1))?;

    let bits = substeps.next_power_of_two().ilog2();
    let bytes = (bits + 7) / 8;

    let mut arms = Vec::new();
    let mut index = if dynamic_step.is_some() { (1 << bits) - data.variants.len() + 1 } else { 0 };

    let bytes_literal = Literal::usize_unsuffixed(usize::try_from(bytes).unwrap());

    for v in data.variants.iter() {
        let ident = &v.ident;

        if is_dynamic_step(v) {
            arms.extend(quote!(
                Self::#ident(i) => generic_array::GenericArray::from_slice(&i.to_le_bytes()[0..#bytes_literal]).to_owned(),
            ));
        } else {
            // generate a single variant for static steps
            let index_literal = Literal::usize_suffixed(index);
            arms.extend(quote!(
                Self::#ident => generic_array::GenericArray::from_slice(&#index_literal.to_le_bytes()[0..#bytes_literal]).to_owned(),
            ));
            index += 1;
        }
    }

    let length_type = format_ident!("U{bytes}");

    Ok(quote!(
        impl crate::protocol::step::Step for #ident {
            #[cfg(feature = "compact-gate")]
            type Length = typenum::#length_type;

            #[cfg(feature = "compact-gate")]
            fn as_bytes(&self) -> generic_array::GenericArray<u8, Self::Length> {
                match self {
                    #(#arms)*
                }
            }
        }
    ))
}

fn is_dynamic_step(variant: &syn::Variant) -> bool {
    variant.attrs.iter().any(|x| x.path().is_ident("dynamic"))
}

/// Returns the number literal argument passed to #[dynamic(...)] attribute.
///
/// # Errors
/// Returns an error if the argument format is invalid or the number of steps
/// exceeds `MAX_DYNAMIC_STEPS`. The error can be used to generate a compile
/// time error. The function assumes that `is_dynamic_step()` returns true for
/// the given variant.
fn get_dynamic_step_count(variant: &syn::Variant) -> Result<usize, syn::Error> {
    let dynamic_attr = variant
        .attrs
        .iter()
        .find(|x| x.path().is_ident("dynamic"))
        .unwrap();
    let arg = dynamic_attr
        .parse_args::<syn::LitInt>()
        .map(|x| x.base10_parse::<usize>().unwrap())
        .ok();
    match arg {
        // guard against gigantic code generation
        Some(n) if n <= MAX_DYNAMIC_STEPS => Ok(n),
        _ => Err(syn::Error::new_spanned(
            dynamic_attr,
            format!(
                "ipa_macros::step \"dynamic\" attribute expects a number of steps \
                            (<= {}) in parentheses: #[dynamic(...)].",
                MAX_DYNAMIC_STEPS,
            ),
        )),
    }
}
