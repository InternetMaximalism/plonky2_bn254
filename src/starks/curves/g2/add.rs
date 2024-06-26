use ark_bn254::{Fq2, G2Affine};
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    common::eq::{EvalEq, EvalEqCircuit},
    utils::bn254_base_modulus_bigint,
    N_LIMBS, U256,
};

use super::{
    ext::{
        add::{
            add_uint256ext, add_uint256ext_circuit, add_uint256extmul, add_uint256extmul_circuit,
        },
        convert::{uint256ext_to_uint256extmul, uint256ext_to_uint256extmul_circuit},
        is_modulus_zero::{
            eval_is_ext_modulus_zero, eval_is_ext_modulus_zero_circuit,
            generate_is_ext_modulus_zero, IsExtModulusZeroAux, IS_EXT_MODULUS_AUX_ZERO_LEN,
        },
        modulus_zero::{
            eval_ext_modulus_zero, eval_ext_modulus_zero_circuit, generate_ext_modulus_zero,
            ExtModulusZeroAux, EXT_MODULUS_AUX_ZERO_LEN,
        },
        mul::{
            mul_scalar_uint256extmul, mul_scalar_uint256extmul_circuit, mul_uint256ext,
            mul_uint256ext_circuit,
        },
        sub::{
            sub_uint256ext, sub_uint256ext_circuit, sub_uint256extmul, sub_uint256extmul_circuit,
        },
        U256Ext,
    },
    G2,
};

pub(crate) const G2_ADD_AUX_LEN: usize =
    1 + IS_EXT_MODULUS_AUX_ZERO_LEN + 1 + 2 * N_LIMBS + 3 * EXT_MODULUS_AUX_ZERO_LEN;

/// Auxiliary information for the addition of two G2 points
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct G2AddAux<T: Copy + Clone + Default> {
    pub(crate) is_x_eq: T,
    pub(crate) is_x_eq_aux: IsExtModulusZeroAux<T>,
    pub(crate) is_x_eq_filter: T, // is_x_eq_filter = is_x_eq * filter
    pub(crate) lambda: U256Ext<T>,
    pub(crate) lambda_aux: ExtModulusZeroAux<T>,
    pub(crate) x_aux: ExtModulusZeroAux<T>,
    pub(crate) y_aux: ExtModulusZeroAux<T>,
}

/// Generate the result of adding two G2 points and auxiliary information
pub(crate) fn generate_g2_add<F: RichField>(a: G2<F>, b: G2<F>) -> (G2<F>, G2AddAux<F>) {
    let modulus = bn254_base_modulus_bigint();
    let a_ark: G2Affine = a.into();
    let b_ark: G2Affine = b.into();
    let c_ark: G2Affine = (a_ark + b_ark).into();
    let c: G2<F> = c_ark.into();
    let a_i64 = a.to_i64();
    let b_i64 = b.to_i64();
    let c_i64 = c.to_i64();

    let delta_x = sub_uint256ext(b_i64.x, a_i64.x);
    let (is_x_eq, is_x_eq_aux) = generate_is_ext_modulus_zero::<F>(&modulus, &delta_x);

    let (lambda, lambda_i64, lambda_aux) = if !is_x_eq.is_one() {
        let lambda_ark: Fq2 = ((b_ark.y - a_ark.y) / (b_ark.x - a_ark.x)).into();
        let lambda = U256Ext::<F>::from(lambda_ark);
        let lambda_i64 = lambda.to_i64();

        // diff = lambda*(b.x - a.x) - (b.y - a.y)
        let delta_y_ = sub_uint256ext(b_i64.y, a_i64.y);
        let delta_y = uint256ext_to_uint256extmul(delta_y_);
        let lambda_delta_x = mul_uint256ext(lambda_i64, delta_x);
        let diff = sub_uint256extmul(lambda_delta_x, delta_y);
        let lambda_aux = generate_ext_modulus_zero::<F>(&modulus, &diff);
        (lambda, lambda_i64, lambda_aux)
    } else {
        debug_assert_eq!(a_ark.y, b_ark.y);
        let lambda_ark: Fq2 = Fq2::from(3) * a_ark.x * a_ark.x / (Fq2::from(2) * a_ark.y);
        let lambda = U256Ext::<F>::from(lambda_ark);
        let lambda_i64 = lambda.to_i64();

        // diff = 2*a.y*lambda - 3*a.x^2
        let x_sq = mul_uint256ext(a_i64.x, a_i64.x);
        let three_x_sq = mul_scalar_uint256extmul(3, x_sq);
        let lambda_y = mul_uint256ext(lambda_i64, a_i64.y);
        let two_lambda_y = mul_scalar_uint256extmul(2, lambda_y);
        let diff = sub_uint256extmul(two_lambda_y, three_x_sq);
        let lambda_aux = generate_ext_modulus_zero::<F>(&modulus, &diff);
        (lambda, lambda_i64, lambda_aux)
    };

    // diff = lambda^2 -  (a.x + b.x + c.x)
    let ax_bx = add_uint256ext(a_i64.x, b_i64.x);
    let sum_x_ = add_uint256ext(ax_bx, c_i64.x);
    let sum_x = uint256ext_to_uint256extmul(sum_x_);
    let lambda_sq = mul_uint256ext(lambda_i64, lambda_i64);
    let diff = sub_uint256extmul(lambda_sq, sum_x);
    let x_aux = generate_ext_modulus_zero::<F>(&modulus, &diff);

    // diff = lambda*(c.x - a.x) + c.y + a.y
    let c_x_sub_a_x = sub_uint256ext(c_i64.x, a_i64.x);
    let lambda_c_x_sub_a_x = mul_uint256ext(lambda_i64, c_x_sub_a_x);
    let c_y_a_y_ = add_uint256ext(c_i64.y, a_i64.y);
    let c_y_a_y = uint256ext_to_uint256extmul(c_y_a_y_);
    let diff = add_uint256extmul(lambda_c_x_sub_a_x, c_y_a_y);
    let y_aux = generate_ext_modulus_zero::<F>(&modulus, &diff);

    // is_x_eq_filter = is_x_eq * filter but this function is only called
    // when filter is 1, so we just set it to is_x_eq
    let is_x_eq_filter = is_x_eq;

    let aux = G2AddAux {
        is_x_eq,
        is_x_eq_aux,
        is_x_eq_filter,
        lambda,
        lambda_aux,
        x_aux,
        y_aux,
    };
    (c, aux)
}

/// Evaluate the constraint that the sum of two G2 points is a third G2 point
pub(crate) fn eval_g2_add<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    a: G2<P>,
    b: G2<P>,
    c: G2<P>,
    aux: G2AddAux<P>,
) {
    let delta_x = sub_uint256ext(b.x, a.x);
    eval_is_ext_modulus_zero(
        yield_constr,
        filter,
        modulus,
        delta_x,
        aux.is_x_eq,
        aux.is_x_eq_aux,
    );
    let is_x_eq_filter = aux.is_x_eq_filter;
    // is_x_eq_filter = filter * is_x_eq
    yield_constr.constraint(filter * aux.is_x_eq - is_x_eq_filter);
    // is_not_eq_filter = filter * (1 - is_x_eq)
    let is_not_eq_filter = filter - is_x_eq_filter;

    // in the case of a.x != b.x
    let lambda_delta_x = mul_uint256ext(aux.lambda, delta_x);
    let delta_y_ = sub_uint256ext(b.y, a.y);
    let delta_y = uint256ext_to_uint256extmul(delta_y_);
    let diff = sub_uint256extmul(lambda_delta_x, delta_y);
    eval_ext_modulus_zero(
        yield_constr,
        is_not_eq_filter,
        modulus,
        diff,
        aux.lambda_aux,
    );

    // in the case of a.x == b.x
    let x_sq = mul_uint256ext(a.x, a.x);
    let three_x_sq = mul_scalar_uint256extmul(P::Scalar::from_canonical_u64(3).into(), x_sq);
    let lambda_y = mul_uint256ext(aux.lambda, a.y);
    let two_lambda_y = mul_scalar_uint256extmul(P::Scalar::from_canonical_u64(2).into(), lambda_y);
    let diff = sub_uint256extmul(two_lambda_y, three_x_sq);
    eval_ext_modulus_zero(yield_constr, is_x_eq_filter, modulus, diff, aux.lambda_aux);
    // If a.x == b.x, then a must be equal to b, to ensure that a + b is not at
    // infinity
    a.y.eval_eq(yield_constr, is_x_eq_filter, &b.y);

    // diff = lambda^2 -  (a.x + b.x + c.x)
    let ax_bx = add_uint256ext(a.x, b.x);
    let sum_x_ = add_uint256ext(ax_bx, c.x);
    let sum_x = uint256ext_to_uint256extmul(sum_x_);
    let lambda_sq = mul_uint256ext(aux.lambda, aux.lambda);
    let diff = sub_uint256extmul(lambda_sq, sum_x);
    eval_ext_modulus_zero(yield_constr, filter, modulus, diff, aux.x_aux);

    // diff = lambda*(c.x - a.x) + c.y + a.y
    let c_x_sub_a_x = sub_uint256ext(c.x, a.x);
    let lambda_c_x_sub_a_x = mul_uint256ext(aux.lambda, c_x_sub_a_x);
    let c_y_a_y_ = add_uint256ext(c.y, a.y);
    let c_y_a_y = uint256ext_to_uint256extmul(c_y_a_y_);
    let diff = add_uint256extmul(lambda_c_x_sub_a_x, c_y_a_y);
    eval_ext_modulus_zero(yield_constr, filter, modulus, diff, aux.y_aux);
}

pub(crate) fn eval_g2_add_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    a: G2<ExtensionTarget<D>>,
    b: G2<ExtensionTarget<D>>,
    c: G2<ExtensionTarget<D>>,
    aux: G2AddAux<ExtensionTarget<D>>,
) {
    let delta_x = sub_uint256ext_circuit(builder, b.x, a.x);
    eval_is_ext_modulus_zero_circuit(
        builder,
        yield_constr,
        filter,
        modulus,
        delta_x,
        aux.is_x_eq,
        aux.is_x_eq_aux,
    );
    let is_x_eq_filter = aux.is_x_eq_filter;
    // is_x_eq_filter = filter * is_x_eq
    let t = builder.mul_sub_extension(filter, aux.is_x_eq, is_x_eq_filter);
    yield_constr.constraint(builder, t);
    // is_not_eq_filter = filter * (1 - is_x_eq)
    let is_not_eq_filter = builder.sub_extension(filter, is_x_eq_filter);

    // in the case of a.x != b.x
    let lambda_delta_x = mul_uint256ext_circuit(builder, aux.lambda, delta_x);
    let delta_y_ = sub_uint256ext_circuit(builder, b.y, a.y);
    let delta_y = uint256ext_to_uint256extmul_circuit(builder, delta_y_);
    let diff = sub_uint256extmul_circuit(builder, lambda_delta_x, delta_y);
    eval_ext_modulus_zero_circuit(
        builder,
        yield_constr,
        is_not_eq_filter,
        modulus,
        diff,
        aux.lambda_aux,
    );

    // in the case of a.x == b.x
    let x_sq = mul_uint256ext_circuit(builder, a.x, a.x);
    let three = builder.constant_extension(F::Extension::from_canonical_u64(3).into());
    let three_x_sq = mul_scalar_uint256extmul_circuit(builder, three, x_sq);
    let lambda_y = mul_uint256ext_circuit(builder, aux.lambda, a.y);
    let two = builder.constant_extension(F::Extension::from_canonical_u64(2).into());
    let two_lambda_y = mul_scalar_uint256extmul_circuit(builder, two, lambda_y);
    let diff = sub_uint256extmul_circuit(builder, two_lambda_y, three_x_sq);
    eval_ext_modulus_zero_circuit(
        builder,
        yield_constr,
        is_x_eq_filter,
        modulus,
        diff,
        aux.lambda_aux,
    );
    // If a.x == b.x, then a must be equal to b, to ensure that a + b is not at
    // infinity
    a.y.eval_eq_circuit(builder, yield_constr, is_x_eq_filter, &b.y);

    // diff = lambda^2 -  (a.x + b.x + c.x)
    let ax_bx = add_uint256ext_circuit(builder, a.x, b.x);
    let sum_x_ = add_uint256ext_circuit(builder, ax_bx, c.x);
    let sum_x = uint256ext_to_uint256extmul_circuit(builder, sum_x_);
    let lambda_sq = mul_uint256ext_circuit(builder, aux.lambda, aux.lambda);
    let diff = sub_uint256extmul_circuit(builder, lambda_sq, sum_x);
    eval_ext_modulus_zero_circuit(builder, yield_constr, filter, modulus, diff, aux.x_aux);

    // diff = lambda*(c.x - a.x) + c.y + a.y
    let c_x_sub_a_x = sub_uint256ext_circuit(builder, c.x, a.x);
    let lambda_c_x_sub_a_x = mul_uint256ext_circuit(builder, aux.lambda, c_x_sub_a_x);
    let c_y_a_y_ = add_uint256ext_circuit(builder, c.y, a.y);
    let c_y_a_y = uint256ext_to_uint256extmul_circuit(builder, c_y_a_y_);
    let diff = add_uint256extmul_circuit(builder, lambda_c_x_sub_a_x, c_y_a_y);
    eval_ext_modulus_zero_circuit(builder, yield_constr, filter, modulus, diff, aux.y_aux);
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, mem};

    use super::*;
    use crate::starks::{
        curves::g2::{G2, G2_LEN},
        utils::{bn254_base_modulus_extension_target, bn254_base_modulus_packfield},
    };
    use ark_bn254::G2Affine;
    use ark_ff::UniformRand;
    use plonky2::{
        field::{
            extension::Extendable, goldilocks_field::GoldilocksField, polynomial::PolynomialValues,
        },
        hash::hash_types::RichField,
        iop::{ext_target::ExtensionTarget, witness::PartialWitness},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
        util::timing::TimingTree,
    };
    use starky::{
        config::StarkConfig,
        evaluation_frame::{StarkEvaluationFrame, StarkFrame},
        recursive_verifier::{
            add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target,
            verify_stark_proof_circuit,
        },
        stark::Stark,
        util::trace_rows_to_poly_values,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn g2_add_stark() {
        let mut rng = rand::thread_rng();
        let input = (0..1)
            .map(|i| {
                let a = G2Affine::rand(&mut rng);
                let b = if i % 2 == 0 {
                    G2Affine::rand(&mut rng)
                } else {
                    a.clone()
                };
                (a, b)
            })
            .collect::<Vec<_>>();
        let stark = G2AddStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let trace = stark.generate_trace(&input, 8);
        let mut timing = TimingTree::default();
        let proof =
            starky::prover::prove::<F, C, _, D>(stark, &config, trace, &[], &mut timing).unwrap();
        starky::verifier::verify_stark_proof(stark, proof.clone(), &config).unwrap();

        let circuit_config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let degree_bits = proof.proof.recover_degree_bits(&config);
        let proof_t =
            add_virtual_stark_proof_with_pis(&mut builder, &stark, &config, degree_bits, 0, 0);
        verify_stark_proof_circuit::<F, C, _, D>(&mut builder, stark, proof_t.clone(), &config);
        let zero = builder.zero();
        let mut pw = PartialWitness::new();
        set_stark_proof_with_pis_target(&mut pw, &proof_t, &proof, zero);
        let circuit = builder.build::<C>();
        let circuit_proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(circuit_proof).is_ok());
    }

    const G2_ADD_VIEW_LEN: usize = 3 * G2_LEN + 1 + G2_ADD_AUX_LEN;
    #[repr(C)]
    #[derive(Clone, Debug, Default, PartialEq)]
    struct G2AddView<F: Copy + Clone + Default> {
        a: G2<F>,
        b: G2<F>,
        c: G2<F>,
        filter: F,
        aux: G2AddAux<F>,
    }

    impl<T: Copy + Clone + Default> G2AddView<T> {
        fn to_slice(&self) -> &[T] {
            debug_assert_eq!(
                mem::size_of::<G2AddView<T>>(),
                G2_ADD_VIEW_LEN * mem::size_of::<T>()
            );
            unsafe { std::slice::from_raw_parts(self as *const Self as *const T, G2_ADD_VIEW_LEN) }
        }

        fn from_slice(slice: &[T]) -> &Self {
            assert_eq!(slice.len(), G2_ADD_VIEW_LEN);
            unsafe { &*(slice.as_ptr() as *const Self) }
        }
    }

    #[derive(Clone, Copy)]
    struct G2AddStark<F: RichField + Extendable<D>, const D: usize> {
        _phantom: PhantomData<F>,
    }

    impl<F: RichField + Extendable<D>, const D: usize> G2AddStark<F, D> {
        fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }

        fn generate_trace(
            &self,
            input: &[(G2Affine, G2Affine)],
            min_rows: usize,
        ) -> Vec<PolynomialValues<F>> {
            let num_rows = min_rows.max(input.len()).next_power_of_two();
            let mut rows = Vec::<[F; G2_ADD_VIEW_LEN]>::with_capacity(num_rows);
            for (a, b) in input {
                let a: G2<F> = a.clone().into();
                let b: G2<F> = b.clone().into();
                let (c, aux) = super::generate_g2_add::<F>(a, b);
                let view = G2AddView {
                    a,
                    b,
                    c,
                    filter: F::ONE,
                    aux,
                };
                rows.push(view.to_slice().to_vec().try_into().unwrap());
            }
            let default_row: [F; G2_ADD_VIEW_LEN] =
                G2AddView::default().to_slice().to_vec().try_into().unwrap();
            rows.resize(num_rows, default_row);
            trace_rows_to_poly_values(rows)
        }
    }

    impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for G2AddStark<F, D> {
        type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, G2_ADD_VIEW_LEN, 0>
        where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>;

        type EvaluationFrameTarget =
            StarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, G2_ADD_VIEW_LEN, 0>;

        fn eval_packed_generic<FE, P, const D2: usize>(
            &self,
            vars: &Self::EvaluationFrame<FE, P, D2>,
            yield_constr: &mut starky::constraint_consumer::ConstraintConsumer<P>,
        ) where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>,
        {
            let view = G2AddView::from_slice(vars.get_local_values());
            let modulus = bn254_base_modulus_packfield();
            eval_g2_add(
                yield_constr,
                view.filter,
                modulus,
                view.a,
                view.b,
                view.c,
                view.aux,
            );
        }

        fn eval_ext_circuit(
            &self,
            builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
            vars: &Self::EvaluationFrameTarget,
            yield_constr: &mut starky::constraint_consumer::RecursiveConstraintConsumer<F, D>,
        ) {
            let view = G2AddView::from_slice(vars.get_local_values());
            let modulus = bn254_base_modulus_extension_target(builder);
            eval_g2_add_circuit(
                builder,
                yield_constr,
                view.filter,
                modulus,
                view.a,
                view.b,
                view.c,
                view.aux,
            );
        }

        fn constraint_degree(&self) -> usize {
            3
        }
    }
}
