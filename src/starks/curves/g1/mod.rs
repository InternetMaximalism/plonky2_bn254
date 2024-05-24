use ark_bn254::{Fq, G1Affine};
use plonky2::hash::hash_types::RichField;

use crate::starks::{
    modular::{
        is_modulus_zero::{IsModulusZeroAux, IS_MODULUS_AUX_ZERO_LEN},
        modulus_zero::{ModulusZeroAux, MODULUS_AUX_ZERO_LEN},
    },
    N_LIMBS, U256,
};
pub mod add;
pub mod scalar_mul_stark;
pub mod scalar_mul_view;

pub(crate) const G1_LEN: usize = 2 * N_LIMBS;

#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct G1<T: Copy + Clone + Default> {
    pub(crate) x: U256<T>,
    pub(crate) y: U256<T>,
}

impl<F: RichField> From<G1<F>> for G1Affine {
    fn from(g1: G1<F>) -> Self {
        let x = Fq::from(g1.x);
        let y = Fq::from(g1.y);
        G1Affine::new_unchecked(x, y)
    }
}

impl<F: RichField> From<G1Affine> for G1<F> {
    fn from(g1: G1Affine) -> Self {
        G1 {
            x: g1.x.into(),
            y: g1.y.into(),
        }
    }
}

impl<F: RichField> G1<F> {
    pub(crate) fn to_i64(&self) -> G1<i64> {
        G1 {
            x: self.x.to_i64(),
            y: self.y.to_i64(),
        }
    }
}
