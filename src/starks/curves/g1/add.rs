use crate::starks::{
    modular::{
        modular_zero::generate_modulus_zero,
        pol_utils::{pol_add, pol_add_normal, pol_mul_wide, pol_sub, pol_sub_normal},
    },
    utils::bn254_base_modulus_bigint,
    U256,
};
use ark_bn254::{Fq, G1Affine};
use num::Zero as _;
use plonky2::hash::hash_types::RichField;

use super::{G1Aux, G1};

pub(crate) fn generate_g1_add<F: RichField>(a: G1<F>, b: G1<F>) -> (G1<F>, G1Aux<F>) {
    let modulus = bn254_base_modulus_bigint();
    let a_ark: G1Affine = a.into();
    let b_ark: G1Affine = b.into();
    let c_ark: G1Affine = (a_ark + b_ark).into();
    let c: G1<F> = c_ark.into();
    let lambda_ark: Fq = ((b_ark.y - a_ark.y) / (b_ark.x - a_ark.x)).into();
    let a_i64 = a.to_i64();
    let b_i64 = b.to_i64();
    let c_i64 = c.to_i64();
    let lambda = U256::<F>::from(lambda_ark);
    let lambda_i64 = lambda.to_i64();

    // lambda*(b.x - a.x) = b.y - a.y mod p
    let delta_x = pol_sub_normal(b_i64.x.value, a_i64.x.value);
    let delta_y = pol_sub(b_i64.y.value, a_i64.y.value);
    let lambda_delta_x = pol_mul_wide(lambda_i64.value, delta_x);
    let diff = pol_sub_normal(lambda_delta_x, delta_y);
    let lambda_aux = generate_modulus_zero::<F>(&modulus, &diff);

    // lambda^2 = a.x + b.x + c.x mod p
    let ax_add_bx = pol_add_normal(a_i64.x.value, b_i64.x.value);
    let sum_x = pol_add_normal(ax_add_bx, c_i64.x.value);
    let lambda_sq = pol_mul_wide(lambda_i64.value, lambda_i64.value);

    // let (new_x, quot_sign_x, aux_x) = generate_modular_op::<F>(&modulus, new_x_input);
    // let new_x_i64 = positive_column_to_i64(new_x);
    // let x1_minus_new_x = pol_sub_normal(a_x_i64, new_x_i64);
    // let lambda_mul_x1_minus_new_x = pol_mul_wide(lambda_i64, x1_minus_new_x);
    // let mut y1_wide = [0i64; 2 * N_LIMBS - 1];
    // y1_wide[0..N_LIMBS].copy_from_slice(&a_y_i64);
    // let new_y_input = pol_sub_normal(lambda_mul_x1_minus_new_x, y1_wide);
    // let (new_y, quot_sign_y, aux_y) = generate_modular_op::<F>(&modulus, new_y_input);
    // G1Output {
    //     lambda,
    //     new_x,
    //     new_y,
    //     aux_zero,
    //     aux_x,
    //     aux_y,
    //     quot_sign_zero,
    //     quot_sign_x,
    //     quot_sign_y,
    // }
    todo!()
}
