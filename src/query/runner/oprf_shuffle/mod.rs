pub(super) mod query;
mod share;

use self::share::{ShuffleShareBK, ShuffleShareF, ShuffleShareMK};
use crate::protocol::ipa::IPAInputRow;
pub type ShuffleInputRow = IPAInputRow<ShuffleShareF, ShuffleShareMK, ShuffleShareBK>;
