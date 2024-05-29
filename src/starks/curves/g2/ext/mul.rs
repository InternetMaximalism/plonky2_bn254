use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::starks::{
    modular::pol_utils::{
        pol_add_normal, pol_add_normal_ext_circuit, pol_mul_scalar, pol_mul_scalar_ext_circuit,
        pol_mul_wide, pol_mul_wide_ext_circuit, pol_sub_normal, pol_sub_normal_ext_circuit,
    },
    U256,
};

use super::{ArithmeticOps, U256Ext, U256ExtMul};

pub(crate) fn mul_uint256ext<T: ArithmeticOps>(x: U256Ext<T>, y: U256Ext<T>) -> U256ExtMul<T> {
    let x_c0_y_c0 = pol_mul_wide(x.c0.value, y.c0.value);
    let x_c1_y_c1 = pol_mul_wide(x.c1.value, y.c1.value);
    let z_c0 = pol_sub_normal(x_c0_y_c0, x_c1_y_c1);
    let x_c0_y_c1 = pol_mul_wide(x.c0.value, y.c1.value);
    let x_c1_y_c0 = pol_mul_wide(x.c1.value, y.c0.value);
    let z_c1 = pol_add_normal(x_c0_y_c1, x_c1_y_c0);
    U256ExtMul { c0: z_c0, c1: z_c1 }
}

pub(crate) fn mul_uint256ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: U256Ext<ExtensionTarget<D>>,
    y: U256Ext<ExtensionTarget<D>>,
) -> U256ExtMul<ExtensionTarget<D>> {
    let x_c0_y_c0 = pol_mul_wide_ext_circuit(builder, x.c0.value, y.c0.value);
    let x_c1_y_c1 = pol_mul_wide_ext_circuit(builder, x.c1.value, y.c1.value);
    let z_c0 = pol_sub_normal_ext_circuit(builder, x_c0_y_c0, x_c1_y_c1);
    let x_c0_y_c1 = pol_mul_wide_ext_circuit(builder, x.c0.value, y.c1.value);
    let x_c1_y_c0 = pol_mul_wide_ext_circuit(builder, x.c1.value, y.c0.value);
    let z_c1 = pol_add_normal_ext_circuit(builder, x_c0_y_c1, x_c1_y_c0);
    U256ExtMul { c0: z_c0, c1: z_c1 }
}

pub(crate) fn mul_scalar_uint256ext<T: ArithmeticOps>(c: T, x: U256Ext<T>) -> U256Ext<T> {
    let c_x_c0 = pol_mul_scalar(x.c0.value, c);
    let c_x_c1 = pol_mul_scalar(x.c1.value, c);
    U256Ext {
        c0: U256 { value: c_x_c0 },
        c1: U256 { value: c_x_c1 },
    }
}

pub(crate) fn mul_scalar_uint256ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    c: ExtensionTarget<D>,
    x: U256Ext<ExtensionTarget<D>>,
) -> U256Ext<ExtensionTarget<D>> {
    let c_x_c0 = pol_mul_scalar_ext_circuit(builder, x.c0.value, c);
    let c_x_c1 = pol_mul_scalar_ext_circuit(builder, x.c1.value, c);
    U256Ext {
        c0: U256 { value: c_x_c0 },
        c1: U256 { value: c_x_c1 },
    }
}

pub(crate) fn mul_scalar_uint256extmul<T: ArithmeticOps>(c: T, x: U256ExtMul<T>) -> U256ExtMul<T> {
    let c_x_c0 = pol_mul_scalar(x.c0, c);
    let c_x_c1 = pol_mul_scalar(x.c1, c);
    U256ExtMul {
        c0: c_x_c0,
        c1: c_x_c1,
    }
}

pub(crate) fn mul_scalar_uint256extmul_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    c: ExtensionTarget<D>,
    x: U256ExtMul<ExtensionTarget<D>>,
) -> U256ExtMul<ExtensionTarget<D>> {
    let c_x_c0 = pol_mul_scalar_ext_circuit(builder, x.c0, c);
    let c_x_c1 = pol_mul_scalar_ext_circuit(builder, x.c1, c);
    U256ExtMul {
        c0: c_x_c0,
        c1: c_x_c1,
    }
}
