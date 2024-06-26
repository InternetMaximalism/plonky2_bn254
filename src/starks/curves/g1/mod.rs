use ark_bn254::{Fq, G1Affine};
use plonky2::{
    field::{extension::Extendable, packed::PackedField},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    common::eq::{EvalEq, EvalEqCircuit},
    N_LIMBS, U256,
};
pub mod add;
pub mod scalar_mul_ctl;
pub mod scalar_mul_stark;
pub mod scalar_mul_view;

pub(crate) const G1_LEN: usize = 2 * N_LIMBS;

#[repr(C)]
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

impl<T: Copy + Clone + Default> G1<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        debug_assert_eq!(
            std::mem::size_of::<Self>(),
            G1_LEN * std::mem::size_of::<T>()
        );
        unsafe { std::slice::from_raw_parts(self as *const Self as *const T, G1_LEN) }
    }
}

impl<P: PackedField> EvalEq<P> for G1<P> {
    fn eval_eq(&self, yield_constr: &mut ConstraintConsumer<P>, filter: P, other: &Self) {
        self.x.eval_eq(yield_constr, filter, &other.x);
        self.y.eval_eq(yield_constr, filter, &other.y);
    }
}

impl<F: RichField + Extendable<D>, const D: usize> EvalEqCircuit<F, D> for G1<ExtensionTarget<D>> {
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
