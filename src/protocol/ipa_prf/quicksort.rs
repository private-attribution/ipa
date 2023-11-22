use ipa_macros::Step;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        context::Context,
        ipa_prf::boolean_ops::comparison_and_subtraction_low_com::{
            compare_gt,
        },
    },
    secret_sharing::WeakSharedValue,

};
#[derive(Step)]
pub(crate) enum Step {
    Left,
    Right,
    Compare,
}

/// # Errors
/// Will propagate errors from transport and a few typecasts
pub async fn quicksort<C, S>(ctx: C, list: &mut [S]) -> Result<(), Error>
where
    C: Context,
    S: WeakSharedValue,
{
    // check if done
    if list.len() <= 1 {
        return Ok(());
    }

    // precompute comparison against pivot, i.e. list[0] in parallel
    // set up iterator
    let iterator = (&*list).into_iter();

    // first element is pivot
    let pivot = iterator.next().unwrap();

    // generate array of comparison outcomes
    let comp = array![Boolean::Zero;list.len()];

    for (n,m) in iterator.enumerate() {
        comp[n] = compare_gt(ctx.narrow(&Step::Compare), RecordID::from(n), m, pivot).await?
    }

    // swap based on array of comparison outcomes
    let mut i = 0;
    let mut j = list.len() - 1;
    while i <= j {
        while comp[i]==Boolean::ZERO {
            i += 1;
        }
        while comp[j]==Boolean::ONE {
            j -= 1;
        }
        if i <= j {
            list.swap(i, j);
            i += 1;
            j -= 1;
        }
    }

    // recursively call quicksort
    if j > 0 {
        quicksort(ctx.narrow(&Step::Left), &mut list[..j+1]).await?;
    }
    if i < list.len() {
        quicksort(ctx.narrow(&Step::Right),&mut list[i..]).await?;
    }

    Ok(())
}



#[cfg(all(test, unit_test))]
pub mod tests {

}
