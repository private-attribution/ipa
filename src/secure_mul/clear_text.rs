use crate::secure_mul::{RandProvider, SecureMul, H};
use rug::{Complete, Integer};

pub struct H1Clear {
    r_: Integer,
    m: Integer,
    k: Integer,
}

impl H for H1Clear {
    fn combine(&self) -> Integer {
        (&self.m + &self.k).complete()
    }
}

impl RandProvider for H1Clear {
    fn r(&self) -> Integer {
        self.r_.clone()
    }
}

pub struct H2Clear {
    m: Integer,
    k: Integer,
}

impl H for H2Clear {
    fn combine(&self) -> Integer {
        (&self.m + &self.k).complete()
    }
}

pub struct ClearText();

impl SecureMul<H1Clear, H2Clear, H2Clear> for ClearText {
    fn mul(h1: &H1Clear, h2: &H2Clear, h3: &H2Clear) -> Integer {
        let sum = h1.combine() + h2.combine() + h3.combine();
        h1.r() * sum
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::RngCore;
    use rug::rand::RandState;
    use rug::Integer;

    fn rand_int_fn(mut rng: RandState<'_>) -> (impl FnMut() -> Integer + '_) {
        move || Integer::from(Integer::random_bits(256, &mut rng))
    }

    macro_rules! sum_ref {
        (&$e:expr, $(&$es:expr),*) => {
            {
                let mut sum = $e.clone();
                $(
                    sum += &$es;
                )*
                sum
            }
        };
    }

    #[test]
    fn test_mul() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(StdRng::from_entropy().next_u64()));
        let mut rand_int = rand_int_fn(rng);
        let h1 = H1Clear {
            r_: rand_int(),
            m: rand_int(),
            k: rand_int(),
        };
        let h2 = H2Clear {
            m: rand_int(),
            k: rand_int(),
        };
        let h3 = H2Clear {
            m: rand_int(),
            k: rand_int(),
        };

        let res = ClearText::mul(&h1, &h2, &h3);

        assert_eq!(
            res,
            h1.r() * sum_ref!(&h1.m, &h1.k, &h2.m, &h2.k, &h3.m, &h3.k)
        );
    }
}
