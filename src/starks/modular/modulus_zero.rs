use std::fmt::Debug;

use itertools::Itertools;
use num::{Signed, Zero as _};
use num_bigint::{BigInt, Sign};
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field, types::PrimeField64},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    modular::{
        pol_utils::pol_remove_root_2exp,
        utils::{bigint_to_columns, columns_to_bigint},
    },
    LIMB_BITS, N_LIMBS, U256,
};

use super::pol_utils::{
    pol_add_assign, pol_add_assign_ext_circuit, pol_adjoin_root, pol_adjoin_root_ext_circuit,
    pol_mul_wide2, pol_mul_wide2_ext_circuit, pol_sub_assign, pol_sub_assign_ext_circuit,
};

const AUX_COEFF_ABS_MAX: i64 = 1 << 29;

pub(crate) const MODULUS_AUX_ZERO_LEN: usize = 5 * N_LIMBS;

/// Auxiliary information to ensure that the given number is divisible by the modulus
/// Each field except `quot_abs` is subject to range checks of 0 <= x < 2^16
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ModulusZeroAux<F> {
    pub(crate) quot_sign: F,
    pub(crate) quot_abs: [F; N_LIMBS + 1],
    pub(crate) aux_input_lo: [F; 2 * N_LIMBS - 1],
    pub(crate) aux_input_hi: [F; 2 * N_LIMBS - 1],
}

/// Generate auxiliary information to ensure that the given `input`
/// is divisible by the modulus
pub(crate) fn generate_modulus_zero<F: PrimeField64>(
    modulus: &BigInt,
    input: &[i64; 2 * N_LIMBS - 1],
) -> ModulusZeroAux<F> {
    let input_bg = columns_to_bigint(&input);
    debug_assert!(&input_bg % modulus == BigInt::zero());
    let modulus_limbs = bigint_to_columns(modulus);
    let quot = &input_bg / modulus;
    let quot_sign = match quot.sign() {
        Sign::Minus => F::NEG_ONE,
        Sign::NoSign => F::ONE, // if quot == 0 then quot_sign == 1
        Sign::Plus => F::ONE,
    };
    let quot_limbs = bigint_to_columns::<{ N_LIMBS + 1 }>(&quot);
    let quot_abs_limbs = bigint_to_columns::<{ N_LIMBS + 1 }>(&quot.abs());
    // constr_poly = zero_pol  - s(x)*m(x).
    let mut constr_poly = [0i64; 2 * N_LIMBS];
    constr_poly[..2 * N_LIMBS - 1].copy_from_slice(input);
    let prod: [i64; 2 * N_LIMBS] = pol_mul_wide2(quot_limbs, modulus_limbs);
    pol_sub_assign(&mut constr_poly, &prod);
    // aux_limbs = constr/(x- β)
    let mut aux_limbs = pol_remove_root_2exp::<LIMB_BITS, _, { 2 * N_LIMBS }>(constr_poly);
    debug_assert!(aux_limbs[31] == 0);
    for c in aux_limbs.iter_mut() {
        *c += AUX_COEFF_ABS_MAX;
    }
    debug_assert!(aux_limbs.iter().all(|&c| c.abs() <= 2 * AUX_COEFF_ABS_MAX));
    let aux_input_lo = aux_limbs[..2 * N_LIMBS - 1]
        .iter()
        .map(|&c| F::from_canonical_u16(c as u16))
        .collect_vec();
    let aux_input_hi = aux_limbs[..2 * N_LIMBS - 1]
        .iter()
        .map(|&c| F::from_canonical_u16((c >> LIMB_BITS) as u16))
        .collect_vec();
    let quot_abs = quot_abs_limbs.map(|x| F::from_canonical_i64(x));
    ModulusZeroAux {
        quot_sign,
        quot_abs,
        aux_input_lo: aux_input_lo.try_into().unwrap(),
        aux_input_hi: aux_input_hi.try_into().unwrap(),
    }
}

/// Evaluate the constraint that the given `input` is divisible by the modulus
pub(crate) fn eval_modulus_zero<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    input: [P; 2 * N_LIMBS - 1],
    aux: ModulusZeroAux<P>,
) {
    // validate quot_sign
    yield_constr.constraint(filter * (aux.quot_sign * aux.quot_sign - P::ONES));
    let quot = aux
        .quot_abs
        .iter()
        .map(|&limb| aux.quot_sign * limb)
        .collect_vec();
    // constr_poly = q(x) * m(x)
    let mut constr_poly: [_; 2 * N_LIMBS] = pol_mul_wide2(quot.try_into().unwrap(), modulus.value);
    let base = P::Scalar::from_canonical_u64(1 << LIMB_BITS);
    let offset = P::Scalar::from_canonical_u64(AUX_COEFF_ABS_MAX as u64);

    // constr_poly = q(x) * m(x) + (x - β) * s(x)
    let mut aux_poly = [P::ZEROS; 2 * N_LIMBS];
    aux_poly[..2 * N_LIMBS - 1]
        .iter_mut()
        .enumerate()
        .for_each(|(i, c)| {
            *c = aux.aux_input_lo[i] - offset;
            *c += base * aux.aux_input_hi[i];
        });
    pol_add_assign(&mut constr_poly, &pol_adjoin_root(aux_poly, base));

    pol_sub_assign(&mut constr_poly, &input);
    for &c in constr_poly.iter() {
        yield_constr.constraint(filter * c);
    }
}

pub(crate) fn eval_modulus_zero_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    input: [ExtensionTarget<D>; 2 * N_LIMBS - 1],
    aux: ModulusZeroAux<ExtensionTarget<D>>,
) {
    // validate quot_sign
    let one = builder.one_extension();
    let diff = builder.mul_sub_extension(aux.quot_sign, aux.quot_sign, one);
    let t = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, t);

    let quot = aux
        .quot_abs
        .iter()
        .map(|&limb| builder.mul_extension(aux.quot_sign, limb))
        .collect_vec();

    // constr_poly = q(x) * m(x)
    let mut constr_poly: [_; 2 * N_LIMBS] =
        pol_mul_wide2_ext_circuit(builder, quot.try_into().unwrap(), modulus.value);
    // constr_poly = q(x) * m(x) + (x - β) * s(x)
    let offset =
        builder.constant_extension(F::Extension::from_canonical_u64(AUX_COEFF_ABS_MAX as u64));
    let zero = builder.zero_extension();
    let mut aux_poly = [zero; 2 * N_LIMBS];
    let base = F::from_canonical_u64(1u64 << LIMB_BITS);
    aux_poly[..2 * N_LIMBS - 1]
        .iter_mut()
        .enumerate()
        .for_each(|(i, c)| {
            *c = builder.sub_extension(aux.aux_input_lo[i], offset);
            *c = builder.mul_const_add_extension(base, aux.aux_input_hi[i], *c);
        });
    let base = builder.constant_extension(base.into());
    let t = pol_adjoin_root_ext_circuit(builder, aux_poly, base);
    pol_add_assign_ext_circuit(builder, &mut constr_poly, &t);

    // q(x) * m(x) + (x - β) * s(x) - zero_pol = 0
    pol_sub_assign_ext_circuit(builder, &mut constr_poly, &input);
    for &c in constr_poly.iter() {
        let t = builder.mul_extension(filter, c);
        yield_constr.constraint(builder, t);
    }
}
