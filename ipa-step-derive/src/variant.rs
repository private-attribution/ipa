use ipa_step::name::UnderscoreStyle;
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Attribute, DataEnum, ExprPath, Fields, Ident, LitInt, LitStr, Type, TypePath, Variant,
    meta::ParseNestedMeta, spanned::Spanned,
};

use crate::{IntoSpan, sum::ExtendedSum};

struct VariantAttrParser<'a> {
    full_name: String,
    ident: &'a Ident,
    name: Option<String>,
    count: Option<usize>,
    child: Option<ExprPath>,
    integer: Option<TypePath>,
}

impl<'a> VariantAttrParser<'a> {
    fn new(full_name: String, ident: &'a Ident) -> Self {
        Self {
            full_name,
            ident,
            name: None,
            count: None,
            child: None,
            integer: None,
        }
    }

    /// Parse an enum variant.
    fn parse_variant(mut self, variant: &Variant) -> Result<VariantAttribute, syn::Error> {
        if !self.parse_fields(&variant.fields)? {
            return self.make_attr();
        }
        if let Some((_, d)) = &variant.discriminant {
            return d
                .span()
                .error("#[derive(CompactStep)] does not work with discriminants");
        }

        self.parse_attrs(&variant.attrs)
    }

    /// Parse the outer label on a struct or enum.
    fn parse_outer(
        mut self,
        attrs: &[Attribute],
        fields: Option<&Fields>,
    ) -> Result<VariantAttribute, syn::Error> {
        if let Some(fields) = fields {
            self.parse_fields(fields)?;
        }
        self.parse_attrs(attrs)
    }

    fn parse_fields(&mut self, fields: &Fields) -> Result<bool, syn::Error> {
        match &fields {
            Fields::Named(_) => {
                return fields.error("#[derive(CompactStep)] does not support named field");
            }
            Fields::Unnamed(f) => {
                if f.unnamed.len() != 1 {
                    return fields
                        .error("#[derive(CompactStep) only supports empty or integer variants");
                }
                let Some(f) = f.unnamed.first() else {
                    return Ok(false);
                };

                let Type::Path(int_type) = &f.ty else {
                    return f.ty.span().error(
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
        Ok(true)
    }

    fn parse_attrs(mut self, attrs: &[Attribute]) -> Result<VariantAttribute, syn::Error> {
        let Some(attr) = attrs.iter().find(|a| a.path().is_ident("step")) else {
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
            return Err(m.error("#[step(count = ...)] duplicated"));
        }
        if self.integer.is_none() {
            return Err(m.error("#[step(count = ...)] only applies to integer variants"));
        }

        let v: LitInt = m.value()?.parse()?;
        let Ok(v) = v.base10_parse::<usize>() else {
            return v.span().error("#[step(count = ...) invalid value");
        };

        if !(2..1000).contains(&v) {
            return v
                .span()
                .error("#[step(count = ...)] needs to be at least 2 and less than 1000");
        }

        self.count = Some(v);
        Ok(())
    }

    fn parse_name(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.name.is_some() {
            return Err(m.error("#[step(name = ...)] duplicated"));
        }

        let lit_name = m.value()?.parse::<LitStr>()?;
        let n = lit_name.value();
        if n.contains('/') {
            return lit_name.error("#[step(name = ...)] cannot contain '/'");
        }
        self.name = Some(n);
        Ok(())
    }

    fn parse_child(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.child.is_some() {
            return Err(m.error("#[step(child = ...)] duplicated"));
        }

        self.child = Some(m.value()?.parse::<ExprPath>()?);
        Ok(())
    }

    fn make_attr(self) -> Result<VariantAttribute, syn::Error> {
        if self.integer.is_some() && self.count.is_none() {
            self.ident.span().error(
                "#[derive(CompactStep)] requires that integer variants include #[step(count = ...)]",
            )
        } else {
            Ok(VariantAttribute {
                full_name: self.full_name,
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

pub struct VariantAttribute {
    full_name: String,
    ident: Ident,
    name: String,
    integer: Option<(usize, TypePath)>,
    child: Option<ExprPath>,
}

impl VariantAttribute {
    /// The name of this variant.
    /// Either the `name` attribute passed to `#[step(name = "")]` or
    /// a snake case version of the type identifier.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parse a set of attributes out from a representation of an enum.
    pub fn parse_variants(enum_ident: &Ident, data: &DataEnum) -> Result<Vec<Self>, syn::Error> {
        let mut steps = Vec::with_capacity(data.variants.len());
        for v in &data.variants {
            let full_name = format!("{}::{}", enum_ident, v.ident);
            steps.push(VariantAttrParser::new(full_name, &v.ident).parse_variant(v)?);
        }
        Ok(steps)
    }

    /// Parse the attributes from a enum.
    pub fn parse_outer(
        ident: &Ident,
        attrs: &[Attribute],
        fields: Option<&Fields>,
    ) -> Result<Self, syn::Error> {
        VariantAttrParser::new(ident.to_string(), ident).parse_outer(attrs, fields)
    }
}

#[derive(Default)]
pub struct Generator {
    // This keeps a running tally of the total number of steps across all of the variants.
    // This is a composite because it isn't necessarily a simple integer.
    // It might be `<Child as CompactStep>::STEP_COUNT + 4` or similar.
    arm_count: ExtendedSum,
    // This tracks the index of each item.
    index_arms: TokenStream,
    // This tracks integer variant constructors.
    int_variant_constructors: TokenStream,
    // This tracks the arrays of names that are used for integer variants.
    name_arrays: TokenStream,
    // This tracks the arms of the `AsRef<str>` match implementation.
    as_ref_arms: TokenStream,
    // This tracks the arms of the `CompactStep::step_string` match implementation.
    step_string_arms: TokenStream,
    // This tracks the arms of a `CompactStep::step_narrow_type` match implementation.
    step_narrow_arms: TokenStream,
}

impl Generator {
    /// The name of this variant.
    /// Generate the code for a single variant.
    /// Return the updated running tally of steps involved.
    pub fn add_variant(&mut self, v: &VariantAttribute) {
        if v.integer.is_none() {
            self.add_empty(v, true);
        } else {
            self.add_int(v, true);
        }
    }

    fn add_outer(&mut self, v: &VariantAttribute) {
        if self.arm_count.is_zero() {
            if v.integer.is_none() {
                self.add_empty(v, false);
            } else {
                self.add_int(v, false);
            }
        } else {
            assert!(
                v.child.is_none(),
                "#[step(child = ...)] is only valid for empty enums"
            );
        }
    }

    fn add_empty(&mut self, v: &VariantAttribute, is_variant: bool) {
        // Unpack so that we can use `quote!()`.
        let VariantAttribute {
            full_name: _,
            ident: step_ident,
            name: step_name,
            integer: None,
            child: step_child,
        } = v
        else {
            unreachable!();
        };

        let arm_count = &self.arm_count; // To make available for `quote!()`.

        let string_value = if is_variant {
            self.index_arms.extend(quote! {
                Self::#step_ident => #arm_count,
            });

            self.as_ref_arms.extend(quote! {
                Self::#step_ident => #step_name,
            });

            quote!(Self::#step_ident.as_ref().to_owned())
        } else {
            // If this is at the top level, don't extend `index_arms` or `as_ref_arms`.
            // We leave these empty so that
            debug_assert!(self.index_arms.is_empty());
            debug_assert!(self.as_ref_arms.is_empty());

            // Empty enums can't be instantiated, so copy the string value out.
            quote!(String::from(#step_name))
        };

        // Use the `AsRef<str>` implementation for the string value.
        self.step_string_arms.extend(quote! {
            _ if i == #arm_count => #string_value,
        });

        let next_arm_count = arm_count.clone() + 1;

        // Variants with children are more complex.
        if let Some(child) = step_child {
            let range_end =
                next_arm_count.clone() + quote!(<#child as ::ipa_step::CompactStep>::STEP_COUNT);

            // The name of each gate is in the form `"this" + "/" + child.step_string(offset)`...
            self.step_string_arms.extend(quote! {
                _ if i < #range_end => #string_value + "/" +
                  &<#child as ::ipa_step::CompactStep>::step_string(i - (#next_arm_count)),
            });

            // We can only narrow from variants that have children.
            // Children might also have variants with children, so then need to asked about those.
            // Note also the `std::any::type_name` kludge here:
            // the belief is that this is better than `stringify!()`
            // on the basis that `#child` might not be fully qualified when specified.
            self.step_narrow_arms.extend(quote! {
                _ if i == #arm_count => Some(::std::any::type_name::<#child>()),
                _ if (#next_arm_count..#range_end).contains(&i)
                  => <#child as ::ipa_step::CompactStep>::step_narrow_type(i - (#next_arm_count)),
            });

            self.arm_count = range_end;
        } else {
            self.arm_count = next_arm_count;
        }
    }

    fn add_int(&mut self, v: &VariantAttribute, is_variant: bool) {
        // Unpack so that we can use `quote!()`.
        let VariantAttribute {
            full_name: step_full_name,
            ident: step_ident,
            name: step_name,
            integer: Some((step_count, step_integer)),
            child: step_child,
        } = v
        else {
            unreachable!();
        };

        let arm_count = &self.arm_count; // To make available for `quote!()`.
        let arm = if is_variant {
            quote!(Self::#step_ident)
        } else {
            quote!(Self)
        };

        if is_variant {
            let constructor = format_ident!("{}", step_ident.to_string().to_snake_case());
            let out_of_bounds_msg = format!(
                "Step index {{v}} out of bounds for {step_full_name} with count {step_count}."
            );
            self.int_variant_constructors.extend(quote! {
                pub fn #constructor(v: #step_integer) -> Self {
                    assert!(
                        v < #step_integer::try_from(#step_count).unwrap(),
                        #out_of_bounds_msg,
                    );
                    Self::#step_ident(v)
                }
            });
        }

        // Construct some nice names for each integer value in the range.
        let array_name = format_ident!("{}_NAMES", step_ident.to_string().to_shouting_case());
        let skip_zeros = match *step_count - 1 {
            1..=9 => 2,
            10..=99 => 1,
            100..=999 => 0,
            _ => unreachable!("step count is too damn high {step_count}"),
        };
        let step_names =
            (0..*step_count).map(|s| step_name.clone() + &format!("{s:03}")[skip_zeros..]);
        let step_count_lit = Literal::usize_unsuffixed(*step_count);
        self.name_arrays.extend(quote! {
            const #array_name: [&str; #step_count_lit] = [#(#step_names),*];
        });

        // Use those names in the `AsRef` implementation.
        self.as_ref_arms.extend(quote! {
             #arm(i) => #array_name[usize::try_from(*i).unwrap()],
        });

        if let Some(child) = step_child {
            let idx = self.arm_count.clone()
                + quote!((<#child as ::ipa_step::CompactStep>::STEP_COUNT + 1) * ::ipa_step::CompactGateIndex::try_from(*i).unwrap());
            let out_of_bounds_msg = format!(
                "Step index {{i}} out of bounds for {step_full_name} with count {step_count}. Consider using bounds-checked step constructors."
            );
            self.index_arms.extend(quote! {
                #arm(i) if *i < #step_integer::try_from(#step_count).unwrap() => #idx,
                #arm(i) => panic!(#out_of_bounds_msg),
            });

            // With `step_count` variations present, each has a name.
            // But each also has independent child nodes of its own.
            // That means `step_count * (#child::STEP_COUNT * 1)` total nodes.
            let range_end = self.arm_count.clone()
                + quote!((<#child as ::ipa_step::CompactStep>::STEP_COUNT + 1) * #step_count_lit);
            self.step_string_arms.extend(quote! {
                _ if i < #range_end => {
                    let offset = i - (#arm_count);
                    let divisor = <#child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                    let s = #arm(#step_integer::try_from(offset / divisor).unwrap()).as_ref().to_owned();
                    if let Some(v) = (offset % divisor).checked_sub(1) {
                        s + "/" + &<#child as ::ipa_step::CompactStep>::step_string(v)
                    } else {
                        s
                    }
               }
            });

            // As above, we need to ask the child about children for their indices.
            // Note: These match clauses can't use the `i < end` shortcut as above, because
            // the match does not cover all options.
            // See also above regarding `std::any::type_name()`.
            self.step_narrow_arms.extend(quote! {
                _ if (#arm_count..#range_end).contains(&i) => {
                    let offset = i - (#arm_count);
                    let divisor = <#child as ::ipa_step::CompactStep>::STEP_COUNT + 1;
                    if let Some(v) = (offset % divisor).checked_sub(1) {
                        <#child as ::ipa_step::CompactStep>::step_narrow_type(v)
                    } else {
                        Some(::std::any::type_name::<#child>())
                    }
                }
            });
            self.arm_count = range_end;
        } else {
            let idx = self.arm_count.clone()
                + quote!(::ipa_step::CompactGateIndex::try_from(*i).unwrap());
            let out_of_bounds_msg = format!(
                "Step index {{i}} out of bounds for {step_full_name} with count {step_count}. Consider using bounds-checked step constructors."
            );
            self.index_arms.extend(quote! {
                #arm(i) if *i < #step_integer::try_from(#step_count).unwrap() => #idx,
                #arm(i) => panic!(#out_of_bounds_msg),
            });

            let range_end = arm_count.clone() + *step_count;
            self.step_string_arms.extend(quote! {
                _ if i < #range_end => #arm(#step_integer::try_from(i - (#arm_count)).unwrap()).as_ref().to_owned(),
            });
            self.arm_count = range_end;
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn generate(mut self, ident: &Ident, attr: &VariantAttribute) -> TokenStream {
        self.add_outer(attr);

        let mut result = quote! {
            impl ::ipa_step::Step for #ident {}
        };

        // Generate a bounds-checking `impl From` if this is an integer unit struct step.
        if let &Some((count, ref type_path)) = &attr.integer {
            let out_of_bounds_msg =
                format!("Step index {{v}} out of bounds for {ident} with count {count}.");
            result.extend(quote! {
                impl From<#type_path> for #ident {
                    fn from(v: #type_path) -> Self {
                        assert!(
                            v < #type_path::try_from(#count).unwrap(),
                            #out_of_bounds_msg,
                        );
                        Self(v)
                    }
                }
            });
        }

        // Generate bounds-checking variant constructors if there are integer variants.
        if !self.int_variant_constructors.is_empty() {
            let constructors = self.int_variant_constructors;
            result.extend(quote! {
                impl #ident {
                    #constructors
                }
            });
        }

        assert_eq!(self.index_arms.is_empty(), self.as_ref_arms.is_empty());
        let (index_arms, as_ref_arms) = if self.index_arms.is_empty() {
            let n = attr.name();
            (quote!(0), quote!(#n))
        } else {
            let index_arms = self.index_arms;
            let as_ref_arms = self.as_ref_arms;
            (
                quote! {
                    match self { #index_arms }
                },
                quote! {
                    match self { #as_ref_arms }
                },
            )
        };

        // Deal with the use of `TryFrom` on types that implement `From`.
        let name_arrays = self.name_arrays;
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
                    #as_ref_arms
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

        let arm_count = self.arm_count;
        let step_string_arms = self.step_string_arms;

        // Maybe override the default implementation of `step_narrow_type`.
        let step_narrow = if self.step_narrow_arms.is_empty() {
            TokenStream::new()
        } else {
            let step_narrow_arms = self.step_narrow_arms;
            quote! {
                fn step_narrow_type(i: ::ipa_step::CompactGateIndex) -> Option<&'static str> {
                    match i {
                        #step_narrow_arms
                        _ => None,
                    }
                }
            }
        };

        result.extend(quote! {
            impl ::ipa_step::CompactStep for #ident {
                const STEP_COUNT: ::ipa_step::CompactGateIndex = #arm_count;
                fn base_index(&self) -> ::ipa_step::CompactGateIndex {
                    #index_arms
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

        result
    }
}
