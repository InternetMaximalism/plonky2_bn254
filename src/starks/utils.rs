use ark_bn254::Fq;
use num::{BigInt, BigUint, FromPrimitive as _};
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use super::{modular::utils::bigint_to_columns, N_LIMBS, U256};

pub(crate) fn bn254_base_modulus_bigint() -> BigInt {
    let neg_one: BigUint = Fq::from(-1).into();
    let modulus_biguint: BigUint = neg_one + BigUint::from_usize(1).unwrap();
    let modulus_bigint: BigInt = modulus_biguint.into();
    modulus_bigint
}

pub(crate) fn bn254_base_modulus_packfield<P: PackedField>() -> U256<P> {
    let modulus_column: [P; N_LIMBS] = bigint_to_columns(&bn254_base_modulus_bigint())
        .map(|x| P::Scalar::from_canonical_u64(x as u64).into());
    U256 {
        value: modulus_column,
    }
}

pub(crate) fn bn254_base_modulus_extension_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> U256<ExtensionTarget<D>> {
    let modulus: [F::Extension; N_LIMBS] = bn254_base_modulus_packfield().value;
    let value = modulus.map(|x| builder.constant_extension(x));
    U256 { value }
}
