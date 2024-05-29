use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::starks::{
    modular::pol_utils::{pol_sub_normal, pol_sub_normal_ext_circuit},
    U256,
};

use super::{ArithmeticOps, U256Ext, U256ExtMul};

pub(crate) fn sub_uint256ext<T: ArithmeticOps>(x: U256Ext<T>, y: U256Ext<T>) -> U256Ext<T> {
    let z_c0 = pol_sub_normal(x.c0.value, y.c0.value);
    let z_c1 = pol_sub_normal(x.c1.value, y.c1.value);
    U256Ext {
        c0: U256 { value: z_c0 },
        c1: U256 { value: z_c1 },
    }
}

pub(crate) fn sub_uint256ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: U256Ext<ExtensionTarget<D>>,
    y: U256Ext<ExtensionTarget<D>>,
) -> U256Ext<ExtensionTarget<D>> {
    let z_c0 = pol_sub_normal_ext_circuit(builder, x.c0.value, y.c0.value);
    let z_c1 = pol_sub_normal_ext_circuit(builder, x.c1.value, y.c1.value);
    U256Ext {
        c0: U256 { value: z_c0 },
        c1: U256 { value: z_c1 },
    }
}

pub(crate) fn sub_uint256extmul<T: ArithmeticOps>(
    x: U256ExtMul<T>,
    y: U256ExtMul<T>,
) -> U256ExtMul<T> {
    let z_c0 = pol_sub_normal(x.c0, y.c0);
    let z_c1 = pol_sub_normal(x.c1, y.c1);
    U256ExtMul { c0: z_c0, c1: z_c1 }
}

pub(crate) fn sub_uint256extmul_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: U256ExtMul<ExtensionTarget<D>>,
    y: U256ExtMul<ExtensionTarget<D>>,
) -> U256ExtMul<ExtensionTarget<D>> {
    let z_c0 = pol_sub_normal_ext_circuit(builder, x.c0, y.c0);
    let z_c1 = pol_sub_normal_ext_circuit(builder, x.c1, y.c1);
    U256ExtMul { c0: z_c0, c1: z_c1 }
}
