use num::BigInt;
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::PrimeField64},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    modular::modulus_zero::{
        eval_modulus_zero, eval_modulus_zero_circuit, generate_modulus_zero, ModulusZeroAux,
        MODULUS_AUX_ZERO_LEN,
    },
    U256,
};

use super::U256ExtMul;

pub(crate) const EXT_MODULUS_AUX_ZERO_LEN: usize = 2 * MODULUS_AUX_ZERO_LEN;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ExtModulusZeroAux<F> {
    pub(crate) c0_aux: ModulusZeroAux<F>,
    pub(crate) c1_aux: ModulusZeroAux<F>,
}

pub(crate) fn generate_ext_modulus_zero<F: PrimeField64>(
    modulus: &BigInt,
    input: &U256ExtMul<i64>,
) -> ExtModulusZeroAux<F> {
    let c0_aux = generate_modulus_zero(modulus, &input.c0);
    let c1_aux = generate_modulus_zero(modulus, &input.c1);
    ExtModulusZeroAux { c0_aux, c1_aux }
}

pub(crate) fn eval_ext_modulus_zero<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    input: U256ExtMul<P>,
    aux: ExtModulusZeroAux<P>,
) {
    eval_modulus_zero(yield_constr, filter, modulus, input.c0, aux.c0_aux);
    eval_modulus_zero(yield_constr, filter, modulus, input.c1, aux.c1_aux);
}

pub(crate) fn eval_ext_modulus_zero_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    input: U256ExtMul<ExtensionTarget<D>>,
    aux: ExtModulusZeroAux<ExtensionTarget<D>>,
) {
    eval_modulus_zero_circuit(builder, yield_constr, filter, modulus, input.c0, aux.c0_aux);
    eval_modulus_zero_circuit(builder, yield_constr, filter, modulus, input.c1, aux.c1_aux);
}
