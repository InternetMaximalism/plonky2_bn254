use ark_bn254::{Fq, Fq2};
use ark_ff::Field as _;
use num::Zero;

pub trait Inv {
    /// If `self` is zero, return zero, otherwise return the inverse of `self`
    fn inv(&self) -> Self;
}

impl Inv for Fq {
    fn inv(&self) -> Fq {
        if self.is_zero() {
            return Fq::zero();
        } else {
            self.inverse().unwrap()
        }
    }
}

impl Inv for Fq2 {
    fn inv(&self) -> Fq2 {
        if self.is_zero() {
            return Fq2::zero();
        } else {
            self.inverse().unwrap()
        }
    }
}
