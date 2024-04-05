// This module exists here because all of this functionality cannot be exported
// from the ipa-step-derive proc-macro crate.  It is only used by build scripts.

use std::{collections::HashMap, env, fs::write, path::PathBuf};

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, parse_str, Ident, Path};

use crate::{name::GateName, CompactGateIndex, CompactStep};

fn crate_path(p: &str) -> String {
    let Some((_, p)) = p.split_once("::") else {
        panic!("unable to handle name of type `{p}`");
    };
    String::from("crate::") + p
}

/// Implement `StepNarrow` for each of the child types in the tree of steps.
fn build_narrows(
    ident: &Ident,
    gate_name: &str,
    step_narrows: HashMap<&str, Vec<CompactGateIndex>>,
    syntax: &mut TokenStream,
) {
    for (t, steps) in step_narrows {
        let t = crate_path(t);
        let ty: Path = parse_str(&t).unwrap();
        let short_name = t.rsplit_once("::").map_or_else(|| t.as_ref(), |(_a, b)| b);
        let msg = format!("unexpected narrow for {gate_name}({{s}}) => {short_name}({{ss}})");
        syntax.extend(quote! {
            impl ::ipa_step::StepNarrow<#ty> for #ident {
                fn narrow(&self, step: &#ty) -> Self {
                    match self.0 {
                        #(#steps)|* => Self(self.0 + 1 + <#ty as ::ipa_step::CompactStep>::base_index(step)),
                        _ => panic!(#msg,
                                    s = self.as_ref(),
                                    ss = <#ty as ::std::convert::AsRef<str>>::as_ref(step)),
                    }
                }
            }
        });
    }
}

/// Write code for the `CompactGate` implementation related to `S` to the determined file.
/// # Panics
/// For various reasons when the type of `S` takes a form that is surprising.
pub fn build<S: CompactStep>() {
    let step_name = crate_path(std::any::type_name::<S>());
    let Some((_, name)) = step_name.rsplit_once("::") else {
        panic!("unable to handle name of type `{step_name}`");
    };
    let name_maker = GateName::new(name);
    let gate_name = name_maker.name();

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(name_maker.filename());
    println!("writing Gate implementation {gate_name} (for {step_name}) to {out:?}");

    let mut step_narrows = HashMap::new();
    step_narrows.insert(std::any::type_name::<S>(), vec![0]); // Add the first step.
    let mut as_ref_arms = TokenStream::new();
    let mut from_arms = TokenStream::new();

    let ident: Ident = parse_str(&gate_name).unwrap();
    for i in 1..=S::STEP_COUNT {
        let s = String::from("/") + &S::step_string(i - 1);
        as_ref_arms.extend(quote! {
            #i => #s,
        });
        from_arms.extend(quote! {
            #s => Ok(#ident(#i)),
        });
        if let Some(t) = S::step_narrow_type(i - 1) {
            step_narrows.entry(t).or_insert_with(Vec::new).push(i);
        }
    }

    let from_panic = format!("unknown string for {gate_name}: \"{{s}}\"");
    let mut syntax = quote! {
        impl ::std::convert::AsRef<str> for #ident {
            fn as_ref(&self) -> &str {
                match self.0 {
                    0 => "/",
                    #as_ref_arms
                    _ => unreachable!(),
                }
            }
        }

        impl ::std::str::FromStr for #ident {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    "/" => Ok(Self::default()),
                    #from_arms
                    _ => Err(format!(#from_panic)),
                }
            }
        }

        impl ::std::convert::From<&str> for #ident {
            fn from(s: &str) -> Self {
                <Self as ::std::str::FromStr>::from_str(s).unwrap_or_else(|e| panic!("{e}"))
            }
        }
    };
    build_narrows(&ident, &gate_name, step_narrows, &mut syntax);

    write(out, prettyplease::unparse(&parse2(syntax).unwrap())).unwrap();
}
