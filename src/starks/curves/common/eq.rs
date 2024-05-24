use plonky2::{
    field::{extension::Extendable, packed::PackedField},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{curves::g1::G1, U256};

pub(crate) trait EvalEq<P: PackedField> {
    fn eval_eq(&self, yield_constr: &mut ConstraintConsumer<P>, filter: P, other: &Self);
}

pub(crate) trait EvalEqCircuit<F: RichField + Extendable<D>, const D: usize> {
    fn eval_eq_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
        filter: ExtensionTarget<D>,
        other: &Self,
    );
}

impl<P: PackedField> EvalEq<P> for P {
    fn eval_eq(&self, yield_constr: &mut ConstraintConsumer<P>, filter: P, other: &Self) {
        yield_constr.constraint(filter * (*self - *other));
    }
}

impl<F: RichField + Extendable<D>, const D: usize> EvalEqCircuit<F, D> for ExtensionTarget<D> {
    fn eval_eq_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
        filter: ExtensionTarget<D>,
        other: &Self,
    ) {
        let t = builder.sub_extension(*self, *other);
        let t_filtered = builder.mul_extension(filter, t);
        yield_constr.constraint(builder, t_filtered);
    }
}

impl<P: PackedField> EvalEq<P> for U256<P> {
    fn eval_eq(&self, yield_constr: &mut ConstraintConsumer<P>, filter: P, other: &Self) {
        for (a, b) in self.value.iter().zip(other.value.iter()) {
            a.eval_eq(yield_constr, filter, b);
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> EvalEqCircuit<F, D>
    for U256<ExtensionTarget<D>>
{
    fn eval_eq_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
        filter: ExtensionTarget<D>,
        other: &Self,
    ) {
        for (a, b) in self.value.iter().zip(other.value.iter()) {
            a.eval_eq_circuit(builder, yield_constr, filter, b);
        }
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
