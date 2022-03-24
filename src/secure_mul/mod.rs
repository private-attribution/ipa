use rug::Integer;

pub mod clear_text;

pub trait H {
    fn combine(&self) -> Integer;
}

pub trait RandProvider {
    fn r(&self) -> Integer;
}

pub trait SecureMul<H1: H + RandProvider, H2: H, H3: H> {
    fn mul(h1: &H1, h2: &H2, h3: &H3) -> Integer;
}
