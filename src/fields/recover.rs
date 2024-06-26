use crate::fields::sgn::Sgn;
use ark_bn254::{Fq, G1Affine};
use ark_ff::Field as _;

pub trait RecoverFromX {
    /// Determine whether y can be recovered from x.
    fn is_recoverable_from_x(x: Fq) -> bool {
        let g: Fq = x * x * x + Fq::from(3);
        g.sqrt().is_some()
    }

    /// Recover a G1 target from the x coordinate.
    /// y's sgn is assumed to be false (even)
    fn recover_from_x(x: Fq) -> G1Affine;
}

impl RecoverFromX for G1Affine {
    fn recover_from_x(x: Fq) -> G1Affine {
        let x_cubed_plus_b: Fq = x * x * x + Fq::from(3);
        let mut y = x_cubed_plus_b.sqrt().unwrap();
        if y.sgn() {
            y = -y;
        }
        G1Affine::new(x, y)
    }
}
