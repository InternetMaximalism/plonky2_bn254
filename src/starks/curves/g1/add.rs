use crate::starks::{
    modular::{
        is_modulus_zero::{
            eval_is_modulus_zero, eval_is_modulus_zero_circuit, generate_is_modulus_zero,
        },
        modulus_zero::{eval_modulus_zero, eval_modulus_zero_circuit, generate_modulus_zero},
        pol_utils::{
            pol_add, pol_add_ext_circuit, pol_add_normal, pol_add_normal_ext_circuit,
            pol_mul_scalar, pol_mul_scalar_ext_circuit, pol_mul_wide, pol_mul_wide_ext_circuit,
            pol_sub, pol_sub_ext_circuit, pol_sub_normal, pol_sub_normal_ext_circuit,
        },
    },
    utils::bn254_base_modulus_bigint,
    U256,
};
use ark_bn254::{Fq, G1Affine};
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

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
    let diff = pol_add_normal(lambda_c_x_sub_a_x, c_y_a_y);
    let y_aux = generate_modulus_zero::<F>(&modulus, &diff);

    // is_x_eq_filter = is_x_eq * filter but this function is only called
    // when filter is 1, so we just set it to is_x_eq
    let is_x_eq_filter = is_x_eq;

    let aux = G1AddAux {
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

pub(crate) fn eval_g1_add<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    a: G1<P>,
    b: G1<P>,
    c: G1<P>,
    aux: G1AddAux<P>,
) {
    let delta_x = pol_sub_normal(b.x.value, a.x.value);
    eval_is_modulus_zero(
        yield_constr,
        filter,
        modulus,
        U256 { value: delta_x },
        aux.is_x_eq,
        aux.is_x_eq_aux,
    );
    let is_x_eq_filter = aux.is_x_eq_filter;
    // is_x_eq_filter = filter * is_x_eq
    yield_constr.constraint(filter * aux.is_x_eq - is_x_eq_filter);
    // is_not_eq_filter = filter * (1 - is_x_eq)
    let is_not_eq_filter = filter - is_x_eq_filter;

    // in the case of a.x != b.x
    let lambda_delta_x = pol_mul_wide(aux.lambda.value, delta_x);
    let delta_y = pol_sub(b.y.value, a.y.value);
    let diff = pol_sub_normal(lambda_delta_x, delta_y);
    eval_modulus_zero(
        yield_constr,
        is_not_eq_filter,
        modulus,
        diff,
        aux.lambda_aux,
    );

    // in the case of a.x == b.x
    let x_sq = pol_mul_wide(a.x.value, a.x.value);
    let three_x_sq = pol_mul_scalar(x_sq, P::Scalar::from_canonical_u64(3).into());
    let lambda_y = pol_mul_wide(aux.lambda.value, a.y.value);
    let two_lambda_y = pol_mul_scalar(lambda_y, P::Scalar::from_canonical_u64(2).into());
    let diff = pol_sub_normal(two_lambda_y, three_x_sq);
    eval_modulus_zero(yield_constr, is_x_eq_filter, modulus, diff, aux.lambda_aux);

    // diff = lambda^2 -  (a.x + b.x + c.x)
    let ax_bx = pol_add_normal(a.x.value, b.x.value);
    let sum_x = pol_add(ax_bx, c.x.value);
    let lambda_sq = pol_mul_wide(aux.lambda.value, aux.lambda.value);
    let diff = pol_sub_normal(lambda_sq, sum_x);
    eval_modulus_zero(yield_constr, filter, modulus, diff, aux.x_aux);

    // diff = lambda*(c.x - a.x) + c.y + a.y
    let c_x_sub_a_x = pol_sub_normal(c.x.value, a.x.value);
    let lambda_c_x_sub_a_x = pol_mul_wide(aux.lambda.value, c_x_sub_a_x);
    let c_y_a_y = pol_add(c.y.value, a.y.value);
    let diff = pol_add_normal(lambda_c_x_sub_a_x, c_y_a_y);
    eval_modulus_zero(yield_constr, filter, modulus, diff, aux.y_aux);
}

pub(crate) fn eval_g1_add_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    a: G1<ExtensionTarget<D>>,
    b: G1<ExtensionTarget<D>>,
    c: G1<ExtensionTarget<D>>,
    aux: G1AddAux<ExtensionTarget<D>>,
) {
    let delta_x = pol_sub_normal_ext_circuit(builder, a.x.value, b.x.value);

    eval_is_modulus_zero_circuit(
        builder,
        yield_constr,
        filter,
        modulus,
        U256 { value: delta_x },
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
    let lambda_delta_x = pol_mul_wide_ext_circuit(builder, aux.lambda.value, delta_x);
    let delta_y = pol_sub_ext_circuit(builder, b.y.value, a.y.value);
    let diff = pol_sub_normal_ext_circuit(builder, lambda_delta_x, delta_y);
    eval_modulus_zero_circuit(
        builder,
        yield_constr,
        is_not_eq_filter,
        modulus,
        diff,
        aux.lambda_aux,
    );

    // in the case of a.x == b.x
    let x_sq = pol_mul_wide_ext_circuit(builder, a.x.value, a.x.value);
    let three = builder.constant_extension(F::Extension::from_canonical_u64(3));
    let three_x_sq = pol_mul_scalar_ext_circuit(builder, x_sq, three);
    let lambda_y = pol_mul_wide_ext_circuit(builder, aux.lambda.value, a.y.value);
    let two = builder.constant_extension(F::Extension::from_canonical_u64(2));
    let two_lambda_y = pol_mul_scalar_ext_circuit(builder, lambda_y, two);
    let diff = pol_sub_normal_ext_circuit(builder, two_lambda_y, three_x_sq);
    eval_modulus_zero_circuit(
        builder,
        yield_constr,
        is_x_eq_filter,
        modulus,
        diff,
        aux.lambda_aux,
    );

    // diff = lambda^2 -  (a.x + b.x + c.x)
    let ax_bx = pol_add_normal_ext_circuit(builder, a.x.value, b.x.value);
    let sum_x = pol_add_ext_circuit(builder, ax_bx, c.x.value);
    let lambda_sq = pol_mul_wide_ext_circuit(builder, aux.lambda.value, aux.lambda.value);
    let diff = pol_sub_normal_ext_circuit(builder, lambda_sq, sum_x);
    eval_modulus_zero_circuit(builder, yield_constr, filter, modulus, diff, aux.x_aux);

    // diff = lambda*(c.x - a.x) + c.y + a.y
    let c_x_sub_a_x = pol_sub_normal_ext_circuit(builder, c.x.value, a.x.value);
    let lambda_c_x_sub_a_x = pol_mul_wide_ext_circuit(builder, aux.lambda.value, c_x_sub_a_x);
    let c_y_a_y = pol_add_ext_circuit(builder, c.y.value, a.y.value);
    let diff = pol_add_normal_ext_circuit(builder, lambda_c_x_sub_a_x, c_y_a_y);
    eval_modulus_zero_circuit(builder, yield_constr, filter, modulus, diff, aux.y_aux);
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use crate::starks::{
        curves::g1::{G1AddAux, G1, G1_ADD_AUX_LEN, G1_LEN},
        utils::{bn254_base_modulus_extension_target, bn254_base_modulus_packfield},
    };
    use ark_bn254::G1Affine;
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
        recursive_verifier::{add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target},
        stark::Stark,
        util::trace_rows_to_poly_values,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn g1_add_stark() {
        let mut rng = rand::thread_rng();
        let input = (0..256)
            .map(|_| {
                let a = G1Affine::rand(&mut rng);
                let b = G1Affine::rand(&mut rng);
                (a, b)
            })
            .collect::<Vec<_>>();
        let stark = G1AddStark::<F, D>::new();
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
        let zero = builder.zero();
        let mut pw = PartialWitness::new();
        set_stark_proof_with_pis_target(&mut pw, &proof_t, &proof, zero);
        let circuit = builder.build::<C>();
        let circuit_proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(circuit_proof).is_ok());
    }

    const G1_ADD_VIEW_LEN: usize = 3 * G1_LEN + 1 + G1_ADD_AUX_LEN;
    #[repr(C)]
    #[derive(Clone, Default)]
    struct G1AddView<F: Copy + Clone + Default> {
        a: G1<F>,
        b: G1<F>,
        c: G1<F>,
        filter: F,
        aux: G1AddAux<F>,
    }

    impl<T: Copy + Clone + Default> G1AddView<T> {
        fn to_slice(&self) -> &[T] {
            unsafe { std::slice::from_raw_parts(self as *const Self as *const T, G1_ADD_VIEW_LEN) }
        }
        fn from_slice(slice: &[T]) -> &Self {
            assert_eq!(slice.len(), G1_ADD_VIEW_LEN);
            unsafe { &*(slice.as_ptr() as *const Self) }
        }
    }

    #[derive(Clone, Copy)]
    struct G1AddStark<F: RichField + Extendable<D>, const D: usize> {
        _phantom: PhantomData<F>,
    }

    impl<F: RichField + Extendable<D>, const D: usize> G1AddStark<F, D> {
        fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }

        fn generate_trace(
            &self,
            input: &[(G1Affine, G1Affine)],
            min_rows: usize,
        ) -> Vec<PolynomialValues<F>> {
            let num_rows = min_rows.max(input.len()).next_power_of_two();
            let mut rows = Vec::<[F; G1_ADD_VIEW_LEN]>::with_capacity(num_rows);
            for (a, b) in input {
                let a: G1<F> = a.clone().into();
                let b: G1<F> = b.clone().into();
                let (c, aux) = super::generate_g1_add::<F>(a, b);
                let view = G1AddView {
                    a,
                    b,
                    c,
                    filter: F::ONE,
                    aux,
                };
                rows.push(view.to_slice().to_vec().try_into().unwrap());
            }
            let default_row: [F; G1_ADD_VIEW_LEN] =
                G1AddView::default().to_slice().to_vec().try_into().unwrap();
            rows.resize(num_rows, default_row);
            trace_rows_to_poly_values(rows)
        }
    }

    impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for G1AddStark<F, D> {
        type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, G1_ADD_VIEW_LEN, 0>
        where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>;

        type EvaluationFrameTarget =
            StarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, G1_ADD_VIEW_LEN, 0>;

        fn eval_packed_generic<FE, P, const D2: usize>(
            &self,
            vars: &Self::EvaluationFrame<FE, P, D2>,
            yield_constr: &mut starky::constraint_consumer::ConstraintConsumer<P>,
        ) where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>,
        {
            let view = G1AddView::from_slice(vars.get_local_values());
            let modulus = bn254_base_modulus_packfield();
            eval_g1_add(
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
            let view = G1AddView::from_slice(vars.get_local_values());
            let modulus = bn254_base_modulus_extension_target(builder);
            eval_g1_add_circuit(
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
