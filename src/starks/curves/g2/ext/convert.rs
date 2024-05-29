use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::starks::{
    modular::pol_utils::{pol_add_normal, pol_add_normal_ext_circuit},
    N_LIMBS, U256,
};

use super::{U256Ext, U256ExtMul};

pub(crate) fn uint256ext_to_uint256extmul<T: Default + Copy>(x: U256Ext<T>) -> U256ExtMul<T> {
    let mut c0 = [T::default(); 2 * N_LIMBS - 1];
    c0[..N_LIMBS].copy_from_slice(&x.c0.value);
    let mut c1 = [T::default(); 2 * N_LIMBS - 1];
    c1[..N_LIMBS].copy_from_slice(&x.c1.value);
    U256ExtMul { c0, c1 }
}

pub(crate) fn add_uint256ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: U256Ext<ExtensionTarget<D>>,
) -> U256ExtMul<ExtensionTarget<D>> {
    let zero = builder.zero_extension();
    let mut c0 = [zero; 2 * N_LIMBS - 1];
    c0[..N_LIMBS].copy_from_slice(&x.c0.value);
    let mut c1 = [zero; 2 * N_LIMBS - 1];
    c1[..N_LIMBS].copy_from_slice(&x.c1.value);
    U256ExtMul { c0, c1 }
}
