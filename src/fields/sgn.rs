use ark_bn254::{Fq, Fq2};
use num::{BigUint, Zero};

pub trait Sgn {
    /// even is false, odd is true
    fn sgn(&self) -> bool;
}

impl Sgn for Fq {
    fn sgn(&self) -> bool {
        let digits = BigUint::from(*self).to_u32_digits();
        if digits.len() == 0 {
            return false;
        } else {
            digits[0] & 1 == 1
        }
    }
}

impl Sgn for Fq2 {
    fn sgn(&self) -> bool {
        let sgn_x = self.c0.sgn();
        let zero_0 = self.c0.is_zero();
        let sgn0_y = self.c1.sgn();
        sgn_x || (zero_0 && sgn0_y)
    }
}
