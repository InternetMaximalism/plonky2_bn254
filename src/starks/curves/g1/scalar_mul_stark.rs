use std::marker::PhantomData;

use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
use num::BigUint;
use plonky2::{
    field::{extension::Extendable, polynomial::PolynomialValues, types::Field},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
};
use starky::{
    evaluation_frame::{StarkEvaluationFrame, StarkFrame},
    lookup::{Column, Lookup},
    stark::Stark,
    util::trace_rows_to_poly_values,
};

use crate::starks::{
    curves::{
        common::{
            eq::{EvalEq, EvalEqCircuit},
            round_flags::{eval_round_flags, eval_round_flags_circuit, generate_round_flags},
            utils::biguint_to_le_bits,
        },
        g1::scalar_mul_view::{NUM_RANGE_CHECK_COLS, N_BITS},
    },
    utils::{bn254_base_modulus_extension_target, bn254_base_modulus_packfield},
};

use super::{
    add::{eval_g1_add, eval_g1_add_circuit, generate_g1_add, G1AddAux},
    scalar_mul_view::{
        G1ScalarMulView, FREQ_COL, G1_SCALAR_MUL_VIEW_LEN, RANGE_CHECK_COLS, RANGE_COUNTER_COL,
    },
};

pub(crate) struct G1ScalarMulInput {
    pub(crate) s: BigUint,
    pub(crate) x: G1Affine,
    pub(crate) offset: G1Affine,
    pub(crate) timestamp: usize,
}

#[derive(Copy, Clone)]
pub(crate) struct G1ScalarMulStark<F: RichField + Extendable<D>, const D: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> G1ScalarMulStark<F, D> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    pub(crate) fn generate_trace(
        &self,
        inputs: &[G1ScalarMulInput],
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        let num_rows = min_rows.max(inputs.len() * N_BITS).next_power_of_two();
        let mut rows = vec![];
        for input in inputs {
            rows.extend(self.generate_one_set(input));
        }
        let default_row = [F::ZERO; G1_SCALAR_MUL_VIEW_LEN];
        rows.resize(num_rows, default_row);
        self.generate_range_checks(&mut rows);
        trace_rows_to_poly_values(rows)
    }

    fn generate_range_checks(&self, rows: &mut Vec<[F; G1_SCALAR_MUL_VIEW_LEN]>) {
        let range_max = 1 << 16;
        for (index, row) in rows.iter_mut().enumerate() {
            if index < range_max {
                row[RANGE_COUNTER_COL] = F::from_canonical_usize(index);
            } else {
                row[RANGE_COUNTER_COL] = F::from_canonical_usize(range_max - 1);
            }
        }
        for row_index in 0..rows.len() {
            for col_index in RANGE_CHECK_COLS {
                let x = rows[row_index][col_index].to_canonical_u64() as usize;
                assert!(x < range_max);
                rows[x][FREQ_COL] += F::ONE;
            }
        }
    }

    // Generate one set of trace of the scalar multiplication
    // s*x + offset
    // assuming s is 256bit value
    fn generate_one_set(&self, input: &G1ScalarMulInput) -> Vec<[F; G1_SCALAR_MUL_VIEW_LEN]> {
        let timestamp = F::from_canonical_usize(input.timestamp);
        let mut rows: Vec<[F; G1_SCALAR_MUL_VIEW_LEN]> = vec![];
        let mut row =
            self.generate_first_row_for_one_set(timestamp, input.s.clone(), input.x, input.offset);
        rows.push(row.to_slice().to_vec().try_into().unwrap());
        for row_index in 1..N_BITS {
            row = self.generate_transition_for_one_set(row_index, &row);
            rows.push(row.to_slice().to_vec().try_into().unwrap());
        }
        let expected_output: G1Affine =
            (input.x.mul_bigint(input.s.to_u64_digits()) + input.offset).into();
        let output: G1Affine = row.sum.into();
        debug_assert_eq!(expected_output, output);
        debug_assert!(row.round_flags.is_last_round.is_one());
        rows
    }

    /// Generate the first row of the trace for one set of scalar multiplication
    /// except for range check column
    fn generate_first_row_for_one_set(
        &self,
        timestamp: F,
        s: BigUint,
        x: G1Affine,
        offset: G1Affine,
    ) -> G1ScalarMulView<F> {
        let round_flags = generate_round_flags::<F>(0, N_BITS);
        let s_bits = biguint_to_le_bits(&s, N_BITS);
        let double = x.into();
        let prev_sum = offset.into();
        let (sum, sum_aux) = if s_bits[0] {
            generate_g1_add(prev_sum, double)
        } else {
            (prev_sum, G1AddAux::default())
        };
        let bits: [F; N_BITS] = s_bits
            .into_iter()
            .map(F::from_bool)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        G1ScalarMulView {
            double,
            double_aux: G1AddAux::default(),
            prev_sum,
            sum,
            sum_aux,
            bits,
            timestamp,
            round_flags,
            filter: F::ONE,
            frequency: F::default(),
            range_counter: F::default(),
        }
    }

    fn generate_transition_for_one_set(
        &self,
        row_index: usize,
        local: &G1ScalarMulView<F>,
    ) -> G1ScalarMulView<F> {
        // rotate bits
        let mut bits = [F::default(); N_BITS];
        for i in 0..N_BITS {
            bits[i] = local.bits[(i + 1) % N_BITS]; // rotate bits to the left
        }
        let cur_bit = bits[0];
        let (double, double_aux) = generate_g1_add(local.double, local.double);
        let prev_sum = local.sum;
        let (sum, sum_aux) = if cur_bit.is_one() {
            generate_g1_add(prev_sum, double)
        } else {
            (prev_sum, G1AddAux::default())
        };
        let timestamp = local.timestamp;
        let round_flags = generate_round_flags(row_index, N_BITS);
        G1ScalarMulView {
            double,
            double_aux,
            prev_sum,
            sum,
            sum_aux,
            bits,
            timestamp,
            round_flags,
            filter: F::ONE,
            frequency: F::default(),
            range_counter: F::default(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for G1ScalarMulStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, G1_SCALAR_MUL_VIEW_LEN, 0>
        where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>;

    type EvaluationFrameTarget =
        StarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, G1_SCALAR_MUL_VIEW_LEN, 0>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut starky::constraint_consumer::ConstraintConsumer<P>,
    ) where
        FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
        P: plonky2::field::packed::PackedField<Scalar = FE>,
    {
        let modulus = bn254_base_modulus_packfield::<P>();
        let local = G1ScalarMulView::from_slice(vars.get_local_values());
        let next = G1ScalarMulView::from_slice(vars.get_next_values());

        // is_last_round is "filtered". In other words, `is_last_round` is affected by the factor of the filter.
        // Therefore, `filter - is_last_round`` becomes "filtered" version of `1 - is_last_round`.
        let is_not_last_round = local.filter - local.round_flags.is_last_round;

        // bit rotation
        for i in 0..N_BITS {
            next.bits[i].eval_eq(
                yield_constr,
                is_not_last_round,
                &local.bits[(i + 1) % N_BITS],
            );
        }

        // round_flags
        eval_round_flags(
            yield_constr,
            N_BITS,
            local.filter,
            local.round_flags,
            next.round_flags.counter,
        );

        // timestamp
        next.timestamp
            .eval_eq(yield_constr, is_not_last_round, &local.timestamp);

        // filter transition
        next.filter
            .eval_eq(yield_constr, is_not_last_round, &local.filter);

        // double
        eval_g1_add(
            yield_constr,
            is_not_last_round,
            modulus,
            local.double,
            local.double,
            next.double,
            next.double_aux,
        );

        // sum
        eval_g1_add(
            yield_constr,
            local.bits[0],
            modulus,
            local.prev_sum,
            local.double,
            local.sum,
            local.sum_aux,
        );

        // next.prev_sum = local.sum if is_not_last_round
        next.prev_sum
            .eval_eq(yield_constr, is_not_last_round, &local.sum);

        // range_counter
        // diff is one or zero
        let diff = next.range_counter - local.range_counter;
        yield_constr.constraint_transition(diff * diff - diff);
        // last range_counter is range_max - 1
        let range_max_minus_one = P::Scalar::from_canonical_usize((1 << 16) - 1);
        yield_constr.constraint_last_row(local.range_counter - range_max_minus_one);
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut starky::constraint_consumer::RecursiveConstraintConsumer<F, D>,
    ) {
        let modulus = bn254_base_modulus_extension_target(builder);
        let local = G1ScalarMulView::from_slice(vars.get_local_values());
        let next = G1ScalarMulView::from_slice(vars.get_next_values());

        // is_last_round is "filtered". In other words, `is_last_round` is affected by the factor of the filter.
        // Therefore, `filter - is_last_round`` becomes "filtered" version of `1 - is_last_round`.
        let is_not_last_round =
            builder.sub_extension(local.filter, local.round_flags.is_last_round);

        // bit rotation
        for i in 0..N_BITS {
            next.bits[i].eval_eq_circuit(
                builder,
                yield_constr,
                is_not_last_round,
                &local.bits[(i + 1) % N_BITS],
            );
        }

        // round_flags
        eval_round_flags_circuit(
            builder,
            yield_constr,
            N_BITS,
            local.filter,
            local.round_flags,
            next.round_flags.counter,
        );

        // timestamp
        next.timestamp
            .eval_eq_circuit(builder, yield_constr, is_not_last_round, &local.timestamp);

        // filter transition
        next.filter
            .eval_eq_circuit(builder, yield_constr, is_not_last_round, &local.filter);

        // double
        eval_g1_add_circuit(
            builder,
            yield_constr,
            is_not_last_round,
            modulus,
            local.double,
            local.double,
            next.double,
            next.double_aux,
        );

        // sum
        eval_g1_add_circuit(
            builder,
            yield_constr,
            local.bits[0],
            modulus,
            local.prev_sum,
            local.double,
            local.sum,
            local.sum_aux,
        );

        // next.prev_sum = local.sum if is_not_last_round
        next.prev_sum
            .eval_eq_circuit(builder, yield_constr, is_not_last_round, &local.sum);

        // range_counter
        // diff is one or zero
        let diff = builder.sub_extension(next.range_counter, local.range_counter);
        let t = builder.mul_sub_extension(diff, diff, diff);
        yield_constr.constraint_transition(builder, t);
        // last range_counter is range_max - 1
        let range_max_minus_one =
            builder.constant_extension(F::Extension::from_canonical_usize((1 << 16) - 1));
        let diff = builder.sub_extension(local.range_counter, range_max_minus_one);
        yield_constr.constraint_last_row(builder, diff);
    }

    fn lookups(&self) -> Vec<Lookup<F>> {
        vec![Lookup {
            columns: Column::singles(RANGE_CHECK_COLS).collect(),
            table_column: Column::single(RANGE_COUNTER_COL),
            frequencies_column: Column::single(FREQ_COL),
            filter_columns: vec![Default::default(); NUM_RANGE_CHECK_COLS],
        }]
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn requires_ctls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::starks::curves::common::ctl_values::set_ctl_values_target;
    use crate::starks::curves::common::verifier::recursive_verifier;
    use crate::starks::curves::common::verifier::verify;
    use crate::starks::curves::g1::G1_LEN;
    use crate::starks::curves::{
        common::{prover::prove, utils::tests::random_biguint},
        g1::scalar_mul_ctl::{generate_ctl_values, scalar_mul_ctl},
    };
    use crate::starks::N_LIMBS;
    use ark_bn254::G1Affine;
    use ark_ff::UniformRand;
    use hashbrown::HashMap;
    use plonky2::field::extension::Extendable;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
        util::timing::TimingTree,
    };
    use starky::config::StarkConfig;
    use starky::cross_table_lookup::debug_utils::check_ctls;
    use starky::recursive_verifier::set_stark_proof_target;

    use super::{G1ScalarMulInput, G1ScalarMulStark};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn scalar_mul_stark() {
        let mut rng = rand::thread_rng();
        let num_inputs = 1 << 8;

        let inputs = (0..num_inputs)
            .map(|timestamp| G1ScalarMulInput {
                s: random_biguint(&mut rng),
                x: G1Affine::rand(&mut rng),
                offset: G1Affine::rand(&mut rng),
                timestamp,
            })
            .collect::<Vec<_>>();
        let stark = G1ScalarMulStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let trace = stark.generate_trace(&inputs, 1 << 16);

        let mut timing = TimingTree::default();
        let ctl_values = generate_ctl_values::<F>(&inputs);
        let cross_table_lookups = scalar_mul_ctl();
        let proof = prove::<F, C, _, D>(
            &stark,
            &config,
            &trace,
            &cross_table_lookups,
            &[],
            &mut timing,
        )
        .unwrap();
        check_ctls(&[trace.to_vec()], &cross_table_lookups, &ctl_values);
        verify(
            &stark,
            &config,
            &cross_table_lookups,
            &proof,
            &[],
            &ctl_values,
        )
        .unwrap();

        let degree_bits = proof.proof.recover_degree_bits(&config);
        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let ctl_values_t = add_ctl_values_target(&mut builder, num_inputs);
        let proof_t = recursive_verifier::<F, C, _, D>(
            &mut builder,
            &stark,
            degree_bits,
            &cross_table_lookups,
            &config,
            &ctl_values_t,
        );
        let zero = builder.zero();
        let mut pw = PartialWitness::new();
        set_stark_proof_target(&mut pw, &proof_t.proof, &proof.proof, zero);
        set_ctl_values_target(&mut pw, &ctl_values_t, &ctl_values);
        let circuit = builder.build::<C>();
        let circuit_proof = circuit.prove(pw).unwrap();
        circuit.verify(circuit_proof).unwrap();
    }

    fn add_ctl_values_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        num_inputs: usize,
    ) -> HashMap<usize, Vec<Vec<Target>>> {
        let inputs = (0..num_inputs)
            .map(|_| {
                [(); 2 * G1_LEN + N_LIMBS + 1] // plus one for the timestamp
                    .map(|_| builder.add_virtual_target())
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let outputs = (0..num_inputs)
            .map(|_| {
                [(); G1_LEN + 1] // // plus one for the timestamp
                    .map(|_| builder.add_virtual_target())
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let mut ctl_values_target = HashMap::new();
        ctl_values_target.insert(0, inputs);
        ctl_values_target.insert(1, outputs);
        ctl_values_target
    }
}
