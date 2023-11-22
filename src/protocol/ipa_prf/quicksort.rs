use ipa_macros::Step;
use futures::stream::{iter as stream_iter, TryStreamExt};

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        Field,
        CustomArray,
    },
    protocol::{
        RecordId,
        context::Context,
        basics::Reveal,
        ipa_prf::boolean_ops::comparison_and_subtraction_low_com::{
            compare_gt,
        },
    },
    secret_sharing::{
        WeakSharedValue,
        replicated::semi_honest::AdditiveShare,
    },
    seq_join::seq_join,
};

#[derive(Step)]
pub(crate) enum Step {
    Left,
    Right,
    Compare,
    Reveal,
}

/// insecure quicksort using MPC comparisons
/// This version of quicksort is insecure because it does not enforce the uniqueness of the sorted elements
/// To see why this leaks information: assume that all elements are equal,
/// then quicksort runs in time O(n^2) while for unique elements, it is only expected to run in time O(n log n)
///
/// The leakage can be fixed by appending a counter on each element that is unique to the element
/// This adds another >= log N bits, where N is the amount of elements
///
/// This implementation of quicksort is in place and uses a stack instead of recursion
/// It terminates once the stack is empty
/// # Errors
/// Will propagate errors from transport and a few typecasts
async fn quicksort<C, S>(ctx: C, list: &mut [AdditiveShare<S>]) -> Result<(), Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<S>: IntoIterator<Item = AdditiveShare<S::Element>>,
    S: WeakSharedValue + Field + CustomArray<Element=Boolean>,
{
    // create stack
    let mut stack: Vec<(C,usize,usize)> = vec![];

    // initialize stack
    stack.push((ctx,0usize,list.len()));

    // iterate through recursions
    while !stack.is_empty() {
        // quicksort function:
        // receive bounds on list
        let (ctx, b_l,b_r) = stack.pop().unwrap();

        let (mut i,mut j)=(b_l,b_r-1usize);
        // check whether sort is needed
        if i<j {
            // set up iterator
            let mut iterator = (&list[b_l..b_r]).into_iter();
            // first element is pivot
            let pivot = iterator.next().unwrap();
            // precompute comparison against pivot and reveal result in parallel
            let pctx = &ctx;
            let comp = seq_join(
                ctx.active_work(),
                stream_iter(iterator.enumerate().map( |(n,x)| {
                    async move {
                        let sh_comp=compare_gt(
                            pctx.narrow(&Step::Compare),
                            RecordId::from(n),
                            x,
                            &pivot
                        ).await?;

                        // reveal comparison
                        sh_comp.reveal(pctx.narrow(&Step::Reveal), RecordId::from(n)).await
                    }
                }))
            ).try_collect::<Vec<_>>().await?;

            // swap elements based on comparisons
            while i <= j {
                while comp[i]==Boolean::from(false) {
                    i += 1;
                }
                while comp[j]==Boolean::from(true) {
                    j -= 1;
                }
                if i <= j {
                    list.swap(i, j);
                    i += 1;
                    j -= 1;
                }
            }

            // push recursively calls to quicksort function on stack
            if j > b_l {
                stack.push((ctx.narrow(&Step::Left), b_l, j+1usize));
            }
            if i < b_r {
                stack.push((ctx.narrow(&Step::Right), i, b_r));
            }
        }
    }

    // no error happened, sorted successfully
    Ok(())
}



#[cfg(all(test, unit_test))]
pub mod tests {

}
