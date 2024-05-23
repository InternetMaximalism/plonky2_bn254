use ark_bn254::Fq;
use num::{BigInt, BigUint, One as _, Zero as _};
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::PrimeField64},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    modular::{
        modulus_zero::generate_modulus_zero,
        pol_utils::{pol_mul_wide, pol_sub_normal},
        utils::columns_to_bigint,
    },
    N_LIMBS, U256,
};

use super::{
    modulus_zero::{
        eval_modulus_zero, eval_modulus_zero_circuit, ModulusZeroAux, MODULUS_AUX_ZERO_LEN,
    },
    pol_utils::{pol_mul_scalar, pol_mul_scalar_ext_circuit, pol_mul_wide_ext_circuit},
};

pub(crate) const IS_MODULUS_AUX_ZERO_LEN: usize = N_LIMBS + MODULUS_AUX_ZERO_LEN;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IsModulusZeroAux<F> {
    pub(crate) inv: U256<F>,
    pub(crate) modulus_zero_aux: ModulusZeroAux<F>,
}

/// Generate auxiliary information to determine if the given `value`
/// is divisible by the modulus
pub(crate) fn generate_is_modulus_zero<F: RichField>(
    modulus: &BigInt,
    input: &U256<i64>,
) -> (F, IsModulusZeroAux<F>) {
    let input_bg = columns_to_bigint(&input.value);
    let inv_fq: Fq = {
        let mut temp = &input_bg % modulus;
        if temp < BigInt::zero() {
            temp += modulus;
        }
        if temp.is_zero() {
            Fq::zero()
        } else {
            Fq::one() / Fq::from(temp.to_biguint().unwrap())
        }
    };
    let inv = U256::<F>::from(inv_fq);
    let is_zero = inv_fq.is_zero() as i64;
    let inv_i64 = inv.to_i64();
    // diff = input * inv - 1 + is_zero
    let mut diff = pol_mul_wide(input.value, inv_i64.value);
    diff[0] += is_zero - 1;
    let modulus_zero_aux = generate_modulus_zero::<F>(modulus, &diff);
    (
        F::from_canonical_i64(is_zero),
        IsModulusZeroAux {
            inv,
            modulus_zero_aux,
        },
    )
}

/// Evaluate the constraint that the given `input` is divisible by the modulus
pub(crate) fn eval_is_modulus_zero<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    input: U256<P>,
    is_zero: P,
    aux: IsModulusZeroAux<P>,
) {
    let mut diff = pol_mul_wide(input.value, aux.inv.value);
    diff[0] += is_zero - P::ONES;
    eval_modulus_zero(yield_constr, filter, modulus, diff, aux.modulus_zero_aux);
    let is_zero_mul_input = pol_mul_scalar(input.value, is_zero);
    for limb in is_zero_mul_input {
        yield_constr.constraint(filter * limb);
    }
}

pub(crate) fn eval_is_modulus_zero_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    input: U256<ExtensionTarget<D>>,
    is_zero: ExtensionTarget<D>,
    aux: IsModulusZeroAux<ExtensionTarget<D>>,
) {
    let mut diff = pol_mul_wide_ext_circuit(builder, input.value, aux.inv.value);
    let one = builder.one_extension();
    let is_zero_minus_one = builder.sub_extension(is_zero, one);
    diff[0] = builder.sub_extension(diff[0], is_zero_minus_one);
    eval_modulus_zero_circuit(
        builder,
        yield_constr,
        filter,
        modulus,
        diff,
        aux.modulus_zero_aux,
    );
    let is_zero_mul_input = pol_mul_scalar_ext_circuit(builder, input.value, is_zero);
    for limb in is_zero_mul_input {
        let t = builder.mul_extension(filter, limb);
        yield_constr.constraint(builder, t);
    }
}
