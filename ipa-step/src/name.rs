// Internal-use module used to help with consistent naming of objects.

/// A utility trait that decorates string-ish things and produces
/// `names_like_this` or `NAMES_LIKE_THIS` from `NamesLikeThis`.
///
/// This doesn't use `Cow<'_, str>` as a more generic implementation might.
/// No anticipated use of this trait will avoid having to modify the input.
pub trait UnderscoreStyle {
    fn to_snake_case(&self) -> String {
        self.to_underscore(false)
    }

    fn to_shouting_case(&self) -> String {
        self.to_underscore(true)
    }

    fn to_underscore(&self, upper: bool) -> String;
}

impl<T: AsRef<str>> UnderscoreStyle for T {
    fn to_underscore(&self, upper: bool) -> String {
        self.as_ref().chars().fold(String::new(), |mut acc, c| {
            if c.is_uppercase() {
                if !acc.is_empty() {
                    acc.push('_');
                }
                acc.push(if upper { c } else { c.to_ascii_lowercase() });
            } else {
                acc.push(if upper { c.to_ascii_uppercase() } else { c });
            }
            acc
        })
    }
}

pub struct GateName<'a> {
    s: &'a str,
}

impl<'a> GateName<'a> {
    #[must_use]
    pub fn new(s: &'a str) -> Self {
        Self { s }
    }

    #[must_use]
    pub fn name(&self) -> String {
        self.s.strip_suffix("Step").unwrap_or(self.s).to_string() + "Gate"
    }

    #[must_use]
    pub fn filename(&self) -> String {
        self.name().to_snake_case() + ".rs"
    }
}
