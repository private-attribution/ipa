use std::io;

pub fn generate_events(
    _total_count: u32,
    _epoch: u8,
    _secret_share: bool,
    _seed: &Option<u64>,
    _out: &mut Box<dyn io::Write>,
) -> (u32, u32) {
    (0, 0)
}
