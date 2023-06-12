use crate::tree::Node;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::{
    collections::{HashMap, VecDeque},
    io::Read,
    path::PathBuf,
};
use syn::{parse_macro_input, punctuated::Punctuated, DeriveInput, PathArguments, PathSegment};

// TODOs:
// 1. Proc macro to annotate each step enum/struct to generate `impl StepNarrow<StepX> for Compact` in
//   the same file, rather than giant implementations in the `Compact` file.
//   - This will require a way to get the name of the file (module path) that the macro is being called from.
//   - We could use https://doc.rust-lang.org/proc_macro/struct.Span.html#method.source_file, but it's in nightly.
//   - This will also allow us to generate state transition match statements from int to int rather than str to int.
//
// 2. Enable compile-time detection of steps that are `narrow`ed but never trigger `send` in the protocol.
//   - `Descriptive` gate allows unnecessary `narrow` even if the step doesn't trigger `send`.
//   - There are a couple of reasons this could happen:
//     (a) A step is narrowed, but doesn't trigger `send` before the next narrow.
//     (b) A step is narrowed, but the `send` is conditionally executed. (i.e., `do_the_binary_tree_thing`)
//     (c) any more cases?
//   - We want to detect these cases at compile time and fail the build but need to be able to support (b).
//   - For (b), we could use another proc macro, which is described in the next point #3.
//
// 3. (Done) Allow `narrow`ing of steps that are conditionally executed.
//   - `Compact` gate code is generated from the steps file, which doesn't contain any information about
//     steps that are not executed. However, some protocols narrow the context in advance for convenience.
//     Such narrowing to unknown state will cause the `Compact` gate to panic.
//   - There are two ways to solve this:
//     (a) Allow `narrow`ing from any state to that state. We could do this either by 1) hard coding or by
//         2) annotating the steps that are conditionally executed. We need to take into consideration about
//         a case where there are child steps branching off from the conditional step.
//     (b) Forcibly execute conditional steps when `step-trace` feature is on to generate the steps file.
//         Not sure what is the best way to do this, or whether this will work though.
//  - Currently, we are doing (a-1). It could let unexpected state transitions happen without panicking, but
//    there isn't a better way to solve this.
//
//   Examples:
//   - crate::protocol::boolean::random_bits_generator::FallbackStep
//     This step is only executed when generated random secret shared bits are of a share larger than
//     `2^32 - 5`. However, the context is narrowed to this step when a RBG instance is created. This one
//     is easy to solve by allowing to narrow to a hard-coded state as there are no branching child steps.
//   - crate::protocol::attribution::Step::CurrentCreditOrCreditUpdate
//     This and other similar steps in the "binary tree prefixed sum" protocols are highly optimized such
//     that they are executed (or not executed) depending on the iteration/depth of the loop. To solve this,
//     we could apply the same conditions used to call `multiply` using these contexts to where we `narrow`
//     the context. The code becomes a bit messy, but it's doable.
//   - crate::protocol::context::UpgradeStep
//     This steps is executed in both malicious and semi-honest contexts, but the `narrow` call in semi-honest
//     context is a dummy; it doesn't trigger `send`. This is a bit tricky to solve because 1) there are many
//     child steps, and 2) malicious context
//
// 4. (Done) Generate state transitions of dynamic steps. (i.e., BitOpStep)
//   - There are steps that are dynamically generated based on the number of bits, rows, etc. Fortunately,
//     these steps have finite number of states, so we can generate the state transitions either in steps
//     file generation or in compile time. Again, we need to take into consideration about the case where
//     there are child steps branching off from the dynamic step.
//   - Currently we do this in `collect_steps.py`. In the future, we want to do this in compile time with
//     a proc macro, but that requires a feature currently in nightly (mentioned in #1).
//
// 5. num-multi-bits
//   - `num-multi-bits` also changes the state transition map. We could generate the steps file for all
//     possible values of `num-multi-bits, but that will make the file huge. We can probably just stick to
//     the current empirical best value of 3. We could also try to read the value from the source or the
//     config file, and generate the steps file accordingly. However, the value could change after the steps
//     file is generated, so we need to make sure that the steps file is always up to date somehow.
//
// 6. Root step
//   - In IPA dev, the root step is always `protocol/run-0`. How do we handle this in real-world case with
//     the Compact gate?

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
//
//
// Currently, this derive notation assumes it annotates the `Compact` struct defined in
// `src/protocol/step/compact.rs`. The `Compact` struct is a wrapper around a `u16` value that
// represents the current state of the IPA protocol.
//
// In the future, we might change the macro to annotate each step in the IPA protocol. The macro
// will then generate both `Descriptive` and `Compact` implementations for the step. However, that
// kind of derive macro requires more annotations such as the fully qualified module path of the
// step. This is because there are many locally-defined `Step` enums in IPA, and we need to
// disambiguate them. However, proc macro doesn't receive the fully qualified module path of the
// annotated struct.

#[derive(Clone, Debug)]
struct StepMetaData {
    id: u16,
    depth: u8,
    module: String,
    name: String,
    path: String,
}

impl StepMetaData {
    pub fn new(id: u16, depth: u8, module: &str, name: &str, path: &str) -> Self {
        Self {
            id,
            depth,
            module: module.to_owned(),
            name: name.to_owned(),
            path: path.to_owned(),
        }
    }
}

const TARGET_CRATE: &str = "ipa";
#[cfg(not(feature = "trybuild"))]
const STEPS_FILE_NAME: &str = "steps.txt";
#[cfg(feature = "trybuild")]
const STEPS_FILE_NAME: &str = "steps.test.txt";

/// Generate a state transition graph and the corresponding `StepNarrow` implementations for the
/// IPA protocol.
pub fn expand(item: TokenStream) -> TokenStream {
    // `item` is the `struct Compact(u16)` in AST
    let ast = parse_macro_input!(item as DeriveInput);
    let gate = &ast.ident;
    match &ast.data {
        syn::Data::Struct(_) => {}
        _ => panic!("derive Gate expects a struct"),
    }

    // we omit the fully qualified module path here because we want to be able to test the macro
    // using our own implementations of `Step` and `StepNarrow`.
    let mut expanded = quote!(
        impl Step for #gate {}
    );

    let steps = ipa_state_transition_map();
    let grouped_steps = group_by_modules(&steps);
    let mut reverse_map = Vec::new();

    for (module, steps) in grouped_steps {
        // generate the `StepNarrow` implementation for each module
        let module = module_string_to_ast(&module);
        let states = steps.iter().map(|s| {
            let new_state = &s.name;
            let new_state_id = s.id;
            let previous_state_id = s.get_parent().unwrap().id;
            quote!(
                (#previous_state_id, #new_state) => #new_state_id,
            )
        });
        expanded.extend(quote!(
            impl StepNarrow<#module> for #gate {
                fn narrow(&self, step: &#module) -> Self {
                    Self(match (self.0, step.as_ref()) {
                        #(#states)*
                        _ => static_state_map(self.0, step.as_ref()),
                    })
                }
            }
        ));

        // generate the reverse map for `impl AsRef<str> for Compact`
        // this is used to convert a state ID to a string representation of the state.
        reverse_map.extend(steps.iter().map(|s| {
            let path = &s.path;
            let state_id = s.id;
            quote!(
                #state_id => #path,
            )
        }));
    }

    expanded.extend(quote!(
        impl AsRef<str> for #gate {
            fn as_ref(&self) -> &str {
                match self.0 {
                    #(#reverse_map)*
                    _ => static_reverse_state_map(self.0),
                }
            }
        }
    ));

    expanded.into()
}

/// Generate the state transition map. This is implemented as a tree where each node represents
/// a narrowed step. The root node represents the root step, and each child node represents a
/// narrowed step. The tree is generated by reading the steps file where each line represents a
/// hierarchy of steps delimited by "/".
fn ipa_state_transition_map() -> Node<StepMetaData> {
    let steps = read_steps_file(STEPS_FILE_NAME)
        .into_iter()
        .enumerate()
        .map(|(i, path)| {
            let id = u16::try_from(i + 1).unwrap();
            let path_list = path
                .split("/")
                .map(|s| split_step_module_and_name(s))
                .collect::<Vec<_>>();
            let depth = u8::try_from(path_list.len()).unwrap();
            let (module, name) = path_list.last().unwrap();
            // `path` is used to construct the AsRef implementation.
            // strip the module parts from all steps to reduce the memory footprint.
            let path = path_list
                .iter()
                .map(|(_, name)| name.to_owned())
                .collect::<Vec<_>>()
                .join("/");
            StepMetaData::new(id, depth, module, name, &path)
        })
        .collect::<Vec<_>>();

    construct_tree(steps)
}

/// Reads the steps file and returns a vector of strings, where each string represents a line in the file.
fn read_steps_file(file_path: &str) -> Vec<String> {
    // construct the path to the steps file saved in the same directory as this file
    let mut path = PathBuf::from(file!());
    path.pop();
    path.push(file_path);

    // expect that there's always a steps file
    let mut file = std::fs::File::open(path).expect("Could not open the steps file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    contents.lines().map(|s| s.to_owned()).collect::<Vec<_>>()
}

/// Constructs a tree structure with nodes that contain the `Step` instances.
/// Tree structure helps us to easily find the parent of the current step.
fn construct_tree(steps: Vec<StepMetaData>) -> Node<StepMetaData> {
    let root = Node::new(StepMetaData::new(0, 0, TARGET_CRATE, "root", "root"));
    let mut last_node = root.clone();

    // This logic is based on the assumption that the steps file is sorted by alphabetical order,
    // so that steps are grouped by their parents. Another way of doing this is to introduce
    // another loop to find the parent node from `steps`, but that would be O(n^2).
    for step in steps {
        let delta = i32::try_from(last_node.depth).unwrap() - i32::try_from(step.depth).unwrap();
        let parent = {
            // The implication of the following statement is that, if `delta` is:
            //   = -1, the new state has transitioned one level down. `last_node` is my parent.
            //   = 0, the new state is on the same level. This step shares the same parent with `last_node`.
            //   > 0, the new state has transitioned `delta` levels up. i.e., `delta = 1` means `last_node`'s grandparent is my parent.
            for _ in 0..=delta {
                last_node = last_node.get_parent().unwrap();
            }
            last_node
        };
        last_node = parent.add_child(step);
    }
    root
}

/// Split a single substep full path into the module path and the step's name.
///
/// # Example
/// input = "ipa::protocol::modulus_conversion::convert_shares::Step::xor1"
/// output = ("ipa::protocol::modulus_conversion::convert_shares::Step", "xor1")
fn split_step_module_and_name(input: &str) -> (String, String) {
    let mod_parts = input.split("::").map(|s| s.to_owned()).collect::<Vec<_>>();
    let (substep_name, path) = mod_parts.split_last().unwrap();
    (path.join("::"), substep_name.to_owned())
}

/// Parse the input string as a module path, and output the module AST and the step's name.
///
/// # Panics
/// If the given string is not a valid module path.
fn module_string_to_ast(module: &str) -> syn::Path {
    let mod_parts = module.split("::").map(|s| s.to_owned()).collect::<Vec<_>>();

    let mut segments = Punctuated::new();
    for (i, v) in mod_parts.iter().enumerate() {
        // if the path segment starts with "ipa", replace it with "crate" to make it a relative path
        let segment = if i == 0 && v == TARGET_CRATE {
            "crate"
        } else {
            v
        };

        segments.push(PathSegment {
            ident: format_ident!("{}", segment),
            arguments: PathArguments::None,
        });
    }
    syn::Path {
        leading_colon: None,
        segments,
    }
}

/// Traverse the tree and group the nodes by their module paths. This is required because sub-steps
/// that are defined in the same enum could be narrowed from different parents.
///
/// # Example
/// RootStep/StepA::A1
/// RootStep/StepC::C1/StepD::D2/StepA::A2
///
/// If we generate code for each node while traversing, we will end up with the following:
///
/// ```ignore
/// impl StepNarrow<StepA> for Compact { ... }
/// impl StepNarrow<StepC> for Compact { ... }
/// impl StepNarrow<StepD> for Compact { ... }
/// impl StepNarrow<StepA> for Compact { ... }  // error: conflicting implementation of `StepNarrow<StepA>`
/// ```
///
/// Since rust does not allow multiple occurrences of the same impl block, we need to group the nodes.
fn group_by_modules(root: &Node<StepMetaData>) -> HashMap<String, Vec<Node<StepMetaData>>> {
    let mut result: HashMap<String, Vec<Node<StepMetaData>>> = HashMap::new();
    let mut queue = VecDeque::new();
    queue.extend(root.get_children());

    while let Some(current) = queue.pop_front() {
        if let Some(node) = result.get_mut(&current.module) {
            node.push(current.clone());
        } else {
            result.insert(current.module.clone(), vec![current.clone()]);
        }
        queue.extend(current.get_children());
    }

    result
}

mod tests {
    #[test]
    fn parse_path() {
        let path = super::module_string_to_ast("crate::protocol::attribution::Step::xor1");

        assert_eq!(path.segments.len(), 5);
        assert_eq!(path.segments[0].ident.to_string(), "crate");
        assert_eq!(path.segments[1].ident.to_string(), "protocol");
        assert_eq!(path.segments[2].ident.to_string(), "attribution");
        assert_eq!(path.segments[3].ident.to_string(), "Step");
        assert_eq!(path.segments[4].ident.to_string(), "xor1");

        let path = super::module_string_to_ast("Step::xor1");
        assert_eq!(path.segments.len(), 2);
        assert_eq!(path.segments[0].ident.to_string(), "Step");
        assert_eq!(path.segments[1].ident.to_string(), "xor1");
    }

    #[test]
    #[should_panic]
    fn invalid_path() {
        let _ = super::module_string_to_ast("::Step");
    }
}
