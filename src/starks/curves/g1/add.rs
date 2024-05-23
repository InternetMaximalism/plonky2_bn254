use crate::starks::{
    modular::{
        is_modulus_zero::generate_is_modulus_zero,
        modulus_zero::generate_modulus_zero,
        pol_utils::{
            pol_add, pol_add_normal, pol_mul_scalar, pol_mul_wide, pol_sub, pol_sub_normal,
        },
    },
    utils::bn254_base_modulus_bigint,
    U256,
};
use ark_bn254::{Fq, G1Affine};
use num::Zero as _;
use plonky2::hash::hash_types::RichField;

use super::{G1AddAux, G1};

pub(crate) fn generate_g1_add<F: RichField>(a: G1<F>, b: G1<F>) -> (G1<F>, G1AddAux<F>) {
    let modulus = bn254_base_modulus_bigint();
    let a_ark: G1Affine = a.into();
    let b_ark: G1Affine = b.into();
    let c_ark: G1Affine = (a_ark + b_ark).into();
    let c: G1<F> = c_ark.into();
    let a_i64 = a.to_i64();
    let b_i64 = b.to_i64();
    let c_i64 = c.to_i64();

    let delta_x = pol_sub_normal(b_i64.x.value, a_i64.x.value);
    let (is_x_eq, is_x_eq_aux) = generate_is_modulus_zero::<F>(&modulus, &U256 { value: delta_x });

    let (lambda, lambda_i64, lambda_aux) = if !is_x_eq.is_one() {
        let lambda_ark: Fq = ((b_ark.y - a_ark.y) / (b_ark.x - a_ark.x)).into();
        let lambda = U256::<F>::from(lambda_ark);
        let lambda_i64 = lambda.to_i64();

        // diff = lambda*(b.x - a.x) - (b.y - a.y)
        let delta_y = pol_sub(b_i64.y.value, a_i64.y.value);
        let lambda_delta_x = pol_mul_wide(lambda_i64.value, delta_x);
        let diff = pol_sub_normal(lambda_delta_x, delta_y);
        let lambda_aux = generate_modulus_zero::<F>(&modulus, &diff);
        (lambda, lambda_i64, lambda_aux)
    } else {
        let lambda_ark: Fq = Fq::from(3) * a_ark.x * a_ark.x / (Fq::from(2) * a_ark.y);
        let lambda = U256::<F>::from(lambda_ark);
        let lambda_i64 = lambda.to_i64();

        // diff = 2*a.y*lambda - 3*a.x^2
        let x_sq = pol_mul_wide(a_i64.x.value, a_i64.x.value);
        let three_x_sq = pol_mul_scalar(x_sq, 3);
        let lambda_y = pol_mul_wide(lambda_i64.value, a_i64.y.value);
        let two_lambda_y = pol_mul_scalar(lambda_y, 2);
        let diff = pol_sub_normal(two_lambda_y, three_x_sq);
        let lambda_aux = generate_modulus_zero::<F>(&modulus, &diff);
        (lambda, lambda_i64, lambda_aux)
    };

    // diff = lambda^2 -  (a.x + b.x + c.x)
    let ax_bx = pol_add_normal(a_i64.x.value, b_i64.x.value);
    let sum_x = pol_add(ax_bx, c_i64.x.value);
    let lambda_sq = pol_mul_wide(lambda_i64.value, lambda_i64.value);
    let diff = pol_sub_normal(lambda_sq, sum_x);
    let x_aux = generate_modulus_zero::<F>(&modulus, &diff);

    // diff = lambda*(c.x - a.x) + c.y + a.y
    let c_x_sub_a_x = pol_sub_normal(c_i64.x.value, a_i64.x.value);
    let lambda_c_x_sub_a_x = pol_mul_wide(lambda_i64.value, c_x_sub_a_x);
    let c_y_a_y = pol_add(c_i64.y.value, a_i64.y.value);
    let diff = pol_sub_normal(lambda_c_x_sub_a_x, c_y_a_y);
    let y_aux = generate_modulus_zero::<F>(&modulus, &diff);

    let aux = G1AddAux {
        is_x_eq,
        is_x_eq_aux,
        lambda,
        lambda_aux,
        x_aux,
        y_aux,
    };
    (c, aux)
}
