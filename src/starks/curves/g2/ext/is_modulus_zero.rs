use num::BigInt;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::ConstraintConsumer;
use starky::constraint_consumer::RecursiveConstraintConsumer;

use super::U256Ext;
use crate::starks::modular::is_modulus_zero::eval_is_modulus_zero;
use crate::starks::modular::is_modulus_zero::eval_is_modulus_zero_circuit;
use crate::starks::modular::is_modulus_zero::generate_is_modulus_zero;
use crate::starks::modular::is_modulus_zero::IsModulusZeroAux;
use crate::starks::modular::is_modulus_zero::IS_MODULUS_AUX_ZERO_LEN;
use crate::starks::U256;

pub(crate) const IS_EXT_MODULUS_AUX_ZERO_LEN: usize = 2 + 2 * IS_MODULUS_AUX_ZERO_LEN;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct IsExtModulusZeroAux<F> {
    pub(crate) is_c0_zero: F,
    pub(crate) is_c1_zero: F,
    pub(crate) c0_aux: IsModulusZeroAux<F>,
    pub(crate) c1_aux: IsModulusZeroAux<F>,
}

pub(crate) fn generate_is_ext_modulus_zero<F: RichField>(
    modulus: &BigInt,
    input: &U256Ext<i64>,
) -> (F, IsExtModulusZeroAux<F>) {
    let (is_c0_zero, c0_aux) = generate_is_modulus_zero(modulus, &input.c0);
    let (is_c1_zero, c1_aux) = generate_is_modulus_zero(modulus, &input.c1);
    let is_zero = is_c0_zero * is_c1_zero;
    (
        is_zero,
        IsExtModulusZeroAux {
            is_c0_zero,
            is_c1_zero,
            c0_aux,
            c1_aux,
        },
    )
}

pub(crate) fn eval_is_ext_modulus_zero<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    input: U256Ext<P>,
    is_zero: P,
    aux: IsExtModulusZeroAux<P>,
) {
    yield_constr.constraint(filter * (aux.is_c0_zero * aux.is_c1_zero - is_zero));
    eval_is_modulus_zero(
        yield_constr,
        filter,
        modulus,
        input.c0,
        aux.is_c0_zero,
        aux.c0_aux,
    );
    eval_is_modulus_zero(
        yield_constr,
        filter,
        modulus,
        input.c1,
        aux.is_c1_zero,
        aux.c1_aux,
    );
}

pub(crate) fn eval_is_ext_modulus_zero_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    input: U256Ext<ExtensionTarget<D>>,
    is_zero: ExtensionTarget<D>,
    aux: IsExtModulusZeroAux<ExtensionTarget<D>>,
) {
    let diff = builder.mul_sub_extension(aux.is_c0_zero, aux.is_c1_zero, is_zero);
    let diff_filtered = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, diff_filtered);

    eval_is_modulus_zero_circuit(
        builder,
        yield_constr,
        filter,
        modulus,
        input.c0,
        aux.is_c0_zero,
        aux.c0_aux,
    );
    eval_is_modulus_zero_circuit(
        builder,
        yield_constr,
        filter,
        modulus,
        input.c1,
        aux.is_c1_zero,
        aux.c1_aux,
    );
}
