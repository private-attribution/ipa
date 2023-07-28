use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

/// Add strum::AsRefStr and step::Step trait derives to the annotated enum.
pub fn expand(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::Item);
    let step_enum = match item {
        syn::Item::Enum(e) => e,
        _ => {
            return syn::Error::new_spanned(item, "ipa_macros::step expects an enum")
                .to_compile_error()
                .into()
        }
    };

    add_derives(&step_enum).into()
}

/// Add required derives for the step enum to work with the IPA protocol.
fn add_derives(enum_item: &syn::ItemEnum) -> TokenStream {
    let enum_ident = &enum_item.ident;
    quote!(
        #[derive(AsRefStr, Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[strum(serialize_all = "snake_case")]
        #enum_item

        impl crate::protocol::step::Step for #enum_ident {}
    )
    .into()
}
