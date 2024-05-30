use ark_bn254::Fq2;
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

pub(crate) mod add;
pub(crate) mod convert;
pub(crate) mod is_modulus_zero;
pub(crate) mod modulus_zero;
pub(crate) mod mul;
pub(crate) mod sub;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct U256Ext<T> {
    pub c0: U256<T>,
    pub c1: U256<T>,
}

pub struct U256ExtMul<T> {
    pub c0: [T; 2 * N_LIMBS - 1],
    pub c1: [T; 2 * N_LIMBS - 1],
}

impl<T: Copy + Clone + Default> U256Ext<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const T, 2 * N_LIMBS) }
    }
    pub(super) fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), 2 * N_LIMBS);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}

impl<F: RichField> From<U256Ext<F>> for Fq2 {
    fn from(value: U256Ext<F>) -> Self {
        Fq2::new(value.c0.into(), value.c1.into())
    }
}

impl<F: RichField> From<Fq2> for U256Ext<F> {
    fn from(value: Fq2) -> Self {
        U256Ext {
            c0: value.c0.into(),
            c1: value.c1.into(),
        }
    }
}

impl<F: RichField> U256Ext<F> {
    pub(crate) fn to_i64(&self) -> U256Ext<i64> {
        U256Ext {
            c0: self.c0.to_i64(),
            c1: self.c1.to_i64(),
        }
    }

    pub(crate) fn to_u16(&self) -> U256Ext<u16> {
        U256Ext {
            c0: self.c0.to_u16(),
            c1: self.c1.to_u16(),
        }
    }
}

impl<P: PackedField> EvalEq<P> for U256Ext<P> {
    fn eval_eq(&self, yield_constr: &mut ConstraintConsumer<P>, filter: P, other: &Self) {
        self.c0.eval_eq(yield_constr, filter, &other.c0);
        self.c1.eval_eq(yield_constr, filter, &other.c1);
    }
}

impl<F: RichField + Extendable<D>, const D: usize> EvalEqCircuit<F, D>
    for U256Ext<ExtensionTarget<D>>
{
    fn eval_eq_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
        filter: ExtensionTarget<D>,
        other: &Self,
    ) {
        self.c0
            .eval_eq_circuit(builder, yield_constr, filter, &other.c0);
        self.c1
            .eval_eq_circuit(builder, yield_constr, filter, &other.c1);
    }
}
