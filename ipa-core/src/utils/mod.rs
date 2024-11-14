pub mod array;
pub mod arraychunks;
#[cfg(target_pointer_width = "64")]
mod power_of_two;

#[cfg(target_pointer_width = "64")]
pub use power_of_two::NonZeroU32PowerOfTwo;

/// Replaces all occurrences of `from` with `to` in `s`.
#[allow(dead_code)]
pub fn replace_all(s: &str, from: &str, to: &str) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(from) {
            result.push_str(to);
            i += from.len();
        } else {
            result.push(s.chars().nth(i).unwrap());
            i += 1;
        }
    }
    result
}
