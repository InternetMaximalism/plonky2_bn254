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

pub(crate) const G1_LEN: usize = 2 * N_LIMBS;

#[derive(Clone, Copy, Default)]
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

pub(crate) const G1_ADD_AUX_LEN: usize =
    1 + IS_MODULUS_AUX_ZERO_LEN + 1 + N_LIMBS + 3 * MODULUS_AUX_ZERO_LEN;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct G1AddAux<T: Copy + Clone + Default> {
    pub(crate) is_x_eq: T,
    pub(crate) is_x_eq_aux: IsModulusZeroAux<T>,
    pub(crate) is_x_eq_filter: T, // is_x_eq_filter = is_x_eq * filter
    pub(crate) lambda: U256<T>,
    pub(crate) lambda_aux: ModulusZeroAux<T>,
    pub(crate) x_aux: ModulusZeroAux<T>,
    pub(crate) y_aux: ModulusZeroAux<T>,
}
