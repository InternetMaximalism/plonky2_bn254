use crate::starks::{
    modular::{
        modulus_zero::{
            eval_modulus_zero, eval_modulus_zero_circuit, generate_modulus_zero, ModulusZeroAux,
        },
        pol_utils::{
            pol_mul_wide, pol_mul_wide_ext_circuit, pol_sub_normal, pol_sub_normal_ext_circuit,
        },
    },
    utils::bn254_base_modulus_bigint,
    N_LIMBS, U256,
};
use ark_bn254::Fq;
use plonky2::{
    field::{extension::Extendable, packed::PackedField},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

pub(crate) fn generate_fq_mul<F: RichField>(
    a: U256<F>,
    b: U256<F>,
) -> (U256<F>, ModulusZeroAux<F>) {
    let modulus = bn254_base_modulus_bigint();
    let a_ark: Fq = a.into();
    let b_ark: Fq = b.into();
    let c_ark: Fq = a_ark * b_ark;
    let c = U256::<F>::from(c_ark);
    let a_i64 = a.to_i64();
    let b_i64 = b.to_i64();
    let c_i64 = c.to_i64();
    let a_mul_b_i64 = pol_mul_wide(a_i64.value, b_i64.value);
    let mut c_wide_i64 = [0; 2 * N_LIMBS - 1];
    c_wide_i64[..N_LIMBS].copy_from_slice(&c_i64.value);
    let diff = pol_sub_normal(a_mul_b_i64, c_wide_i64);
    let aux = generate_modulus_zero::<F>(&modulus, &diff);
    (c, aux)
}

/// Evaluate the constraint that the sum of two G1 points is a third G1 point
pub(crate) fn eval_fq_mul<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    a: U256<P>,
    b: U256<P>,
    c: U256<P>,
    aux: ModulusZeroAux<P>,
) {
    let a_mul_b = pol_mul_wide(a.value, b.value);
    let mut c_wide = [P::ZEROS; 2 * N_LIMBS - 1];
    c_wide[..N_LIMBS].copy_from_slice(&c.value);
    let diff = pol_sub_normal(a_mul_b, c_wide);
    eval_modulus_zero(yield_constr, filter, modulus, diff, aux);
}

pub(crate) fn eval_fq_mul_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    a: U256<ExtensionTarget<D>>,
    b: U256<ExtensionTarget<D>>,
    c: U256<ExtensionTarget<D>>,
    aux: ModulusZeroAux<ExtensionTarget<D>>,
) {
    let a_mul_b = pol_mul_wide_ext_circuit(builder, a.value, b.value);
    let zero = builder.zero_extension();
    let mut c_wide = [zero; 2 * N_LIMBS - 1];
    c_wide[..N_LIMBS].copy_from_slice(&c.value);
    let diff = pol_sub_normal_ext_circuit(builder, a_mul_b, c_wide);
    eval_modulus_zero_circuit(builder, yield_constr, filter, modulus, diff, aux);
}
