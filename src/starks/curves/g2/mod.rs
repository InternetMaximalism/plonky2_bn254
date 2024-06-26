use ark_bn254::{Fq2, G2Affine};
use ext::U256Ext;
use plonky2::{
    field::{extension::Extendable, packed::PackedField},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    common::eq::{EvalEq, EvalEqCircuit},
    N_LIMBS,
};

pub(crate) mod add;
pub(crate) mod ext;
pub(crate) mod scalar_mul_ctl;
pub(crate) mod scalar_mul_stark;
pub(crate) mod scalar_mul_view;

pub(crate) const G2_LEN: usize = 4 * N_LIMBS;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub(crate) struct G2<T: Copy + Clone + Default> {
    pub(crate) x: U256Ext<T>,
    pub(crate) y: U256Ext<T>,
}

impl<F: RichField> From<G2<F>> for G2Affine {
    fn from(value: G2<F>) -> Self {
        let x = Fq2::from(value.x);
        let y = Fq2::from(value.y);
        G2Affine::new_unchecked(x, y)
    }
}

impl<F: RichField> From<G2Affine> for G2<F> {
    fn from(value: G2Affine) -> Self {
        G2 {
            x: value.x.into(),
            y: value.y.into(),
        }
    }
}

impl<F: RichField> G2<F> {
    pub(crate) fn to_i64(&self) -> G2<i64> {
        G2 {
            x: self.x.to_i64(),
            y: self.y.to_i64(),
        }
    }
}

impl<T: Copy + Clone + Default> G2<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const T, G2_LEN) }
    }
}

impl<P: PackedField> EvalEq<P> for G2<P> {
    fn eval_eq(&self, yield_constr: &mut ConstraintConsumer<P>, filter: P, other: &Self) {
        self.x.eval_eq(yield_constr, filter, &other.x);
        self.y.eval_eq(yield_constr, filter, &other.y);
    }
}

impl<F: RichField + Extendable<D>, const D: usize> EvalEqCircuit<F, D> for G2<ExtensionTarget<D>> {
    fn eval_eq_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
        filter: ExtensionTarget<D>,
        other: &Self,
    ) {
        self.x
            .eval_eq_circuit(builder, yield_constr, filter, &other.x);
        self.y
            .eval_eq_circuit(builder, yield_constr, filter, &other.y);
    }
}
