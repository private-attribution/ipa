// Procedural macro to derive the Step and StepNarrow traits and generate a memory-efficient gate.
//
// The goal is to generate a state transition graph and the corresponding `StepNarrow` implementations
// for the IPA protocol. This macro assumes that a complete IPA steps file exists in the repo at the
// location specified as `STEPS_FILE`. The steps file can be generated by running `collect_steps.py`.
//
// The steps file contains a list of narrowed steps, where each line represents a hierarchy of narrowed
// steps delimited by "/". For example, the following lines represent a hierarchy of narrowed steps:
//
//     RootStep                                => 0
//     RootStep/StepA::A1                      => 1
//     RootStep/StepA::A1/StepB::B1            => 2
//     RootStep/StepA::A1/StepB::B2            => 3
//     RootStep/StepC::C1                      => 4
//     RootStep/StepC::C1/StepD::D1            => 5
//     RootStep/StepC::C1/StepD::D1/StepA::A2  => 6
//     RootStep/StepC::C2                      => 7
//
// From these lines, we want to generate StepNarrow implementations for each step.
//
//     impl StepNarrow<StepA> for Compact {
//         fn narrow(&self, step: &StepA) -> Self {
//             Self(match (self.0, step.as_ref()) {
//                 (0, "A1") => 1,
//                 (5, "A2") => 6,
//                 _ => panic!("invalid state transition"),
//             })
//         }
//     }
//     impl StepNarrow<StepB> for Compact {
//         fn narrow(&self, step: &StepB) -> Self {
//             Self(match (self.0, step.as_ref()) {
//                 (1, "B1") => 2,
//                 (1, "B2") => 3,
//                 _ => panic!("invalid state transition"),
//             })
//         }
//     }
//     ...

use proc_macro::TokenStream;
use quote::{__private::TokenStream as TokenStream2, format_ident, quote};
use syn::{parse_macro_input, DeriveInput};

use crate::{
    parser::{group_by_modules, ipa_state_transition_map, StepMetaData},
    tree::Node,
};

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
    let mut out = quote!(
        impl crate::protocol::step::Step for #ident {}
    );

    // implement `AsRef<str>`
    extend_or_error!(out, impl_as_ref(&ident, &data));
    // implement `StepNarrow<T>` if `compact-gate` feature is enabled. we need the if
    // statement here to avoid a compile error when `collect_steps.py` is run.
    if cfg!(feature = "compact-gate") {
        extend_or_error!(out, impl_step_narrow(&ident, &data));
    }

    out.into()
}

/// Generate string representations for each variant of the enum. This is
/// similar to what `strum` does, but we have special handling for dynamic
/// steps.
fn impl_as_ref(ident: &syn::Ident, data: &syn::DataEnum) -> Result<TokenStream2, syn::Error> {
    let mut const_arrays = Vec::new();
    let mut arms = Vec::new();
    let mut res = Ok(());

    data.variants.iter().for_each(|v| {
        let ident = &v.ident;
        let ident_snake_case = ident.to_string().to_snake_case();
        let ident_upper_case = ident_snake_case.to_uppercase();

        if is_dynamic_step(v) {
            let num_steps = match get_dynamic_step_count(v) {
                Ok(n) => n,
                Err(e) => {
                    // we can't return from a closure, so we need to set the result and break
                    res = Err(e);
                    return;
                }
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
    });

    res.and(Ok(quote!(
        impl AsRef<str> for #ident {
            fn as_ref(&self) -> &str {
                #(#const_arrays)*
                match self {
                    #(#arms)*
                }
            }
        }
    )))
}

/// Build a state transition map for the enum variants, and use it to generate
/// a `StepNarrow` implementation.
fn impl_step_narrow(ident: &syn::Ident, data: &syn::DataEnum) -> Result<TokenStream2, syn::Error> {
    // get a list of IPA protocol steps from `steps.txt` that match the enum
    let meta = match get_meta_data_for(&ident, &data) {
        Ok(steps) => steps,
        Err(e) => return Err(e),
    };

    // generate match arms for each state transition
    let mut states = Vec::new();
    states.extend(meta.iter().map(|s| {
        let new_state = &s.name;
        let new_state_id = s.id;
        let previous_state_id = s.get_parent().unwrap().id;
        quote!(
            (#previous_state_id, #new_state) => #new_state_id,
        )
    }));

    let panic = quote!(panic!(
        "Invalid state transition: {} -> {}",
        self.0,
        step.as_ref(),
    ));

    let narrow_impl = quote!(
        Self(match (self.0, step.as_ref()) {
            #(#states)*
            _ => #panic,
        })
    );

    Ok(quote!(
        #[cfg(feature = "compact-gate")]
        impl crate::protocol::step::StepNarrow<#ident> for crate::protocol::step::Gate {
            fn narrow(&self, step: &#ident) -> Self {
                #narrow_impl
            }
        }
    ))
}

/// Returns a list of IPA protocol steps from `steps.txt` that match the enum
/// variants in given `data`.
fn get_meta_data_for(
    ident: &syn::Ident,
    data: &syn::DataEnum,
) -> Result<Vec<Node<StepMetaData>>, syn::Error> {
    // Create lists of steps grouped by modules from `steps.txt`.
    let steps = ipa_state_transition_map();
    let grouped_steps = group_by_modules(&steps);

    // Create a list of all enum variant names in the given enum `data`.
    // If a step is narrowed, they will be present in `steps` vec.
    // The dynamic steps are synthetically generated here to cover all
    // subsets in `steps.txt`.
    let variant_names = data
        .variants
        .iter()
        .flat_map(|v| {
            if is_dynamic_step(v) {
                // using `unwrap()` here since we have already validated the
                // format in `impl_as_ref()`.
                let num_steps = get_dynamic_step_count(v).unwrap();
                (0..num_steps)
                    .map(|i| format!("{}{}", v.ident.to_string().to_snake_case(), i))
                    .collect::<Vec<_>>()
            } else {
                vec![v.ident.to_string().to_snake_case()]
            }
        })
        .collect::<Vec<_>>();

    // If there are no variants in the enum, return an empty vector. The
    // caller will need to handle this case properly.
    if variant_names.is_empty() {
        return Ok(Vec::new());
    }

    // Here, we try to find the enum we are expanding from `grouped_steps`.
    // Note that there could be multiple enums with the same name, and the
    // proc-macro does not know the module name it is being used in, so we
    // can't simply use the enum name as a key to look up.
    // Instead, we check whether all steps in `grouped_steps[i]` exist in
    // `variant_names`. If `S ⊆ variant_names where S ∈ grouped_steps`,
    // then we have found our enum. If there are more than one enum that
    // satisfies this condition, we are in trouble...
    let mut target_steps = Vec::new();
    for (_, steps) in grouped_steps {
        if steps.iter().all(|s| {
            s.module.ends_with(ident.to_string().as_str()) && variant_names.contains(&s.name)
        }) {
            target_steps.push(steps);
        }
    }

    match target_steps.len() {
        0 => {
            // If we get here, we have not found the enum in `steps.txt`. It's
            // likely that the enum is newly added but `steps.txt` is not updated,
            // the code where the step is narrowed is no longer executed, or the
            // step is used in tests only.
            Err(syn::Error::new_spanned(
                ident,
                "ipa_macros::step expects an enum with variants that match the steps in \
            steps.txt. If you've made a change to steps, make sure to run `collect_steps.py` \
            and replace steps.txt with the output. If the step is not a part of the protocol \
            yet, you can temporarily hide the step or the module containing the step with \
            `#[cfg(feature = \"descriptive-gate\")]`.",
            ))
        }
        1 => {
            Ok(target_steps[0]
                .iter()
                .map(|s|
                    // we want to retain the references to the parents, so we use `upgrade()`
                    s.upgrade())
                .collect::<Vec<_>>())
        }
        _ => Err(syn::Error::new_spanned(
            ident,
            format!(
                "ipa_macros::step found multiple enums that have the same name and \
            contain at least one variant with the same name. Consider renaming the \
            enum/variant to avoid this conflict.",
            ),
        )),
    }
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
