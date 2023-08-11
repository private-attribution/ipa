use proc_macro::{TokenStream, TokenTree};
use quote::quote;
use syn::{parse_macro_input, parse_quote, Attribute};
#[derive(Default)]
struct StepArgs {
    pub obsolete: bool,
}

impl StepArgs {
    pub fn parse(args: TokenStream) -> Result<Self, syn::Error> {
        let mut step_args = StepArgs::default();

        for arg in args {
            match arg {
                TokenTree::Ident(ident) => match ident.to_string().as_str() {
                    "obsolete" => step_args.obsolete = true,
                    _ => {
                        return Err(syn::Error::new(
                            ident.span().into(),
                            "ipa_macros::step only accepts `obsolete` as an argument",
                        ))
                    }
                },
                TokenTree::Punct(_) => (), // no-op
                _ => {
                    return Err(syn::Error::new(
                        arg.span().into(),
                        "invalid argument passed to ipa_macros::step",
                    ))
                }
            }
        }

        Ok(step_args)
    }
}

/// Replace the `#[step]` attribute with the required derives for the step enum
/// to work with the IPA protocol.
pub fn expand(args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::Item);
    let step_args = match StepArgs::parse(args) {
        Ok(args) => args,
        Err(e) => {
            return TokenStream::from(e.to_compile_error()).into();
        }
    };

    let enum_item = match item {
        syn::Item::Enum(e) => {
            if e.variants.is_empty() {
                return TokenStream::from(
                    syn::Error::new_spanned(
                        e,
                        "ipa_macros::step expects an enum with at least one variant",
                    )
                    .to_compile_error(),
                )
                .into();
            }
            e
        }
        _ => {
            return TokenStream::from(
                syn::Error::new_spanned(item, "ipa_macros::step expects an enum")
                    .to_compile_error(),
            )
            .into();
        }
    };

    add_derives(enum_item, step_args).into()
}

/// Add required derives for the step enum to work with the IPA protocol.
fn add_derives(mut item: syn::ItemEnum, args: StepArgs) -> TokenStream {
    // Attribute proc-macros don't support variant-level attributes. They only
    // support attributes on the enum itself. Usually, when we annotate an enum
    // to mark whether it's obsolete or something else, all variants inherit
    // that annotation (i.e., `AttributionResharableStep`).
    // Instead of making the user annotate all variants one by one, we do it
    // by annotating the enum itself, and internally add the attribute to all
    // variants, and let the derive proc-macro expand.
    item.variants.iter_mut().for_each(|v| {
        if args.obsolete {
            let attr: Attribute = parse_quote!(#[obsolete]);
            v.attrs.push(attr);
        }
    });

    quote!(
        #[derive(Step)]
        #item
    )
    .into()
}
