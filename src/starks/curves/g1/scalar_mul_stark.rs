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
    common::{
        eq::{EvalEq, EvalEqCircuit},
        round_flags::{eval_round_flags, eval_round_flags_circuit, generate_round_flags},
        utils::biguint_to_le_bits,
    },
    curves::g1::scalar_mul_view::{NUM_RANGE_CHECK_COLS, N_BITS},
    utils::{bn254_base_modulus_extension_target, bn254_base_modulus_packfield},
    LIMB_BITS,
};

use super::{
    add::{eval_g1_add, eval_g1_add_circuit, generate_g1_add},
    scalar_mul_view::{
        G1ScalarMulView, FREQ_COL, G1_PERIOD, G1_SCALAR_MUL_VIEW_LEN, RANGE_CHECK_COLS,
        RANGE_COUNTER_COL,
    },
};

pub struct G1ScalarMulInput {
    pub s: BigUint,
    pub x: G1Affine,
    pub offset: G1Affine,
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
        inputs: &[(G1ScalarMulInput, usize)],
        min_rows: usize,
    ) -> Vec<PolynomialValues<F>> {
        let num_rows = min_rows.max(inputs.len() * G1_PERIOD).next_power_of_two();
        let mut rows = vec![];
        for (input, timestamp) in inputs {
            rows.extend(self.generate_one_set(input, *timestamp));
        }
        let default_row = [F::ZERO; G1_SCALAR_MUL_VIEW_LEN];
        rows.resize(num_rows, default_row);
        self.generate_range_checks(&mut rows);
        trace_rows_to_poly_values(rows)
    }

    fn generate_range_checks(&self, rows: &mut Vec<[F; G1_SCALAR_MUL_VIEW_LEN]>) {
        let range_max = 1 << LIMB_BITS;
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
    fn generate_one_set(
        &self,
        input: &G1ScalarMulInput,
        timestamp: usize,
    ) -> Vec<[F; G1_SCALAR_MUL_VIEW_LEN]> {
        let timestamp = F::from_canonical_usize(timestamp);
        let mut rows: Vec<[F; G1_SCALAR_MUL_VIEW_LEN]> = vec![];
        let mut row = self.generate_first_row(timestamp, input.s.clone(), input.x, input.offset);
        rows.push(row.to_slice().to_vec().try_into().unwrap());
        for row_index in 1..G1_PERIOD {
            row = self.generate_transition(row_index, &row);
            rows.push(row.to_slice().to_vec().try_into().unwrap());
        }
        let expected_output: G1Affine =
            (input.x.mul_bigint(input.s.to_u64_digits()) + input.offset).into();
        let output: G1Affine = row.sum.into();
        assert_eq!(expected_output, output);
        assert!(row.round_flags.is_last_round.is_one());
        rows
    }

    /// Generate the first row of the trace for one set of scalar multiplication
    /// except for range check column
    fn generate_first_row(
        &self,
        timestamp: F,
        s: BigUint,
        x: G1Affine,
        offset: G1Affine,
    ) -> G1ScalarMulView<F> {
        let round_flags = generate_round_flags::<F>(0, G1_PERIOD);
        let s_bits = biguint_to_le_bits(&s, N_BITS);
        let bits: [F; N_BITS] = s_bits
            .into_iter()
            .map(F::from_bool)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let double = x.into();
        let a = offset.into();
        let b = double;
        let (c, add_aux) = generate_g1_add(a, b);
        let sum = if bits[0].is_one() { c } else { a };
        G1ScalarMulView {
            double,
            sum,
            a,
            b,
            c,
            add_aux,
            bits,
            timestamp,
            is_adding: F::ONE,
            is_doubling_not_last: F::ZERO,
            round_flags,
            filter: F::ONE,
            frequency: F::default(),
            range_counter: F::default(),
        }
    }

    fn generate_transition(
        &self,
        row_index: usize,
        local: &G1ScalarMulView<F>,
    ) -> G1ScalarMulView<F> {
        if local.is_doubling_not_last.is_one() {
            // next step is adding
            let a = local.sum;
            let b = local.double;
            let (c, add_aux) = generate_g1_add(a, b);
            let mut bits = [F::default(); N_BITS];
            for i in 0..N_BITS {
                bits[i] = local.bits[(i + 1) % N_BITS]; // rotate bits to the
                                                        // left
            }
            let sum = if bits[0].is_one() { c } else { a };
            let round_flags = generate_round_flags(row_index, G1_PERIOD);
            G1ScalarMulView {
                double: local.double,
                sum,
                a,
                b,
                c,
                add_aux,
                bits,
                timestamp: local.timestamp,
                is_adding: F::ONE,
                is_doubling_not_last: F::ZERO,
                round_flags,
                filter: F::ONE,
                frequency: F::default(),
                range_counter: F::default(),
            }
        } else if local.is_adding.is_one() {
            // next step is doubling
            let a = local.double;
            let b = local.double;
            let (c, add_aux) = generate_g1_add(a, b);
            let bits = local.bits;
            let round_flags = generate_round_flags(row_index, G1_PERIOD);
            let is_not_last_round = F::ONE - round_flags.is_last_round;
            G1ScalarMulView {
                double: c,
                sum: local.sum,
                a,
                b,
                c,
                add_aux,
                bits,
                timestamp: local.timestamp,
                is_adding: F::ZERO,
                is_doubling_not_last: is_not_last_round,
                round_flags,
                filter: F::ONE,
                frequency: F::default(),
                range_counter: F::default(),
            }
        } else {
            panic!("Invalid state");
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

        // is_last_round is "filtered". In other words, `is_last_round` is affected by
        // the factor of the filter. Therefore, `filter - is_last_round``
        // becomes "filtered" version of `1 - is_last_round`.
        let is_not_last_round = local.filter - local.round_flags.is_last_round;
        let is_next_not_last_round = next.filter - next.round_flags.is_last_round;

        // check g1 addition
        eval_g1_add(
            yield_constr,
            local.filter,
            modulus,
            local.a,
            local.b,
            local.c,
            local.add_aux,
        );
        // first round should be adding
        local
            .is_adding
            .eval_eq(yield_constr, local.round_flags.is_first_round, &P::ONES);

        // doubling_step -> addition_step
        next.a
            .eval_eq(yield_constr, local.is_doubling_not_last, &local.sum);
        next.b
            .eval_eq(yield_constr, local.is_doubling_not_last, &local.double);
        next.sum.eval_eq(
            yield_constr,
            next.bits[0] * local.is_doubling_not_last,
            &next.c,
        );
        next.sum.eval_eq(
            yield_constr,
            (P::ONES - next.bits[0]) * local.is_doubling_not_last,
            &next.a,
        );
        next.double
            .eval_eq(yield_constr, local.is_doubling_not_last, &local.double);
        next.is_adding
            .eval_eq(yield_constr, local.is_doubling_not_last, &P::ONES);
        next.is_doubling_not_last
            .eval_eq(yield_constr, local.is_doubling_not_last, &P::ZEROS);
        // bit rotation if is_doubling_step and is_not_last_round
        for i in 0..N_BITS {
            next.bits[i].eval_eq(
                yield_constr,
                local.is_doubling_not_last,
                &local.bits[(i + 1) % N_BITS],
            );
        }

        // addition_step -> doubling_step
        next.a.eval_eq(yield_constr, local.is_adding, &local.double);
        next.b.eval_eq(yield_constr, local.is_adding, &local.double);
        next.sum.eval_eq(yield_constr, local.is_adding, &local.sum);
        next.double.eval_eq(yield_constr, local.is_adding, &next.c);
        next.is_adding
            .eval_eq(yield_constr, local.is_adding, &P::ZEROS);
        next.is_doubling_not_last
            .eval_eq(yield_constr, local.is_adding, &is_next_not_last_round);
        // bit is not rotated if is_next_doubling_step
        for i in 0..N_BITS {
            next.bits[i].eval_eq(yield_constr, local.is_adding, &local.bits[i]);
        }

        // round_flags
        eval_round_flags(
            yield_constr,
            G1_PERIOD,
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

        // range_counter
        // diff is one or zero
        let diff = next.range_counter - local.range_counter;
        yield_constr.constraint_transition(diff * diff - diff);
        // last range_counter is range_max - 1
        let range_max_minus_one = P::Scalar::from_canonical_usize((1 << LIMB_BITS) - 1);
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
        let one = builder.one_extension();
        let zero = builder.zero_extension();

        // is_last_round is "filtered". In other words, `is_last_round` is affected by
        // the factor of the filter. Therefore, `filter - is_last_round``
        // becomes "filtered" version of `1 - is_last_round`.
        let is_not_last_round =
            builder.sub_extension(local.filter, local.round_flags.is_last_round);
        let is_next_not_last_round =
            builder.sub_extension(next.filter, next.round_flags.is_last_round);

        // check g1 addition
        eval_g1_add_circuit(
            builder,
            yield_constr,
            local.filter,
            modulus,
            local.a,
            local.b,
            local.c,
            local.add_aux,
        );
        // first round should be adding
        local.is_adding.eval_eq_circuit(
            builder,
            yield_constr,
            local.round_flags.is_first_round,
            &one,
        );

        // doubling_step -> addition_step
        next.a.eval_eq_circuit(
            builder,
            yield_constr,
            local.is_doubling_not_last,
            &local.sum,
        );
        next.b.eval_eq_circuit(
            builder,
            yield_constr,
            local.is_doubling_not_last,
            &local.double,
        );
        let t = builder.mul_extension(next.bits[0], local.is_doubling_not_last);
        next.sum.eval_eq_circuit(builder, yield_constr, t, &next.c);
        let not_next_bit = builder.sub_extension(one, next.bits[0]);
        let t = builder.mul_extension(not_next_bit, local.is_doubling_not_last);
        next.sum.eval_eq_circuit(builder, yield_constr, t, &next.a);
        next.double.eval_eq_circuit(
            builder,
            yield_constr,
            local.is_doubling_not_last,
            &local.double,
        );
        next.is_adding
            .eval_eq_circuit(builder, yield_constr, local.is_doubling_not_last, &one);
        next.is_doubling_not_last.eval_eq_circuit(
            builder,
            yield_constr,
            local.is_doubling_not_last,
            &zero,
        );
        // bit rotation if is_doubling_step and is_not_last_round
        for i in 0..N_BITS {
            next.bits[i].eval_eq_circuit(
                builder,
                yield_constr,
                local.is_doubling_not_last,
                &local.bits[(i + 1) % N_BITS],
            );
        }

        // addition_step -> doubling_step
        next.a
            .eval_eq_circuit(builder, yield_constr, local.is_adding, &local.double);
        next.b
            .eval_eq_circuit(builder, yield_constr, local.is_adding, &local.double);
        next.sum
            .eval_eq_circuit(builder, yield_constr, local.is_adding, &local.sum);
        next.double
            .eval_eq_circuit(builder, yield_constr, local.is_adding, &next.c);
        next.is_adding
            .eval_eq_circuit(builder, yield_constr, local.is_adding, &zero);
        next.is_doubling_not_last.eval_eq_circuit(
            builder,
            yield_constr,
            local.is_adding,
            &is_next_not_last_round,
        );
        // bit is not rotated if is_next_doubling_step
        for i in 0..N_BITS {
            next.bits[i].eval_eq_circuit(builder, yield_constr, local.is_adding, &local.bits[i]);
        }

        // round_flags
        eval_round_flags_circuit(
            builder,
            yield_constr,
            G1_PERIOD,
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

        // range_counter
        // diff is one or zero
        let diff = builder.sub_extension(next.range_counter, local.range_counter);
        let t = builder.mul_sub_extension(diff, diff, diff);
        yield_constr.constraint_transition(builder, t);
        // last range_counter is range_max - 1
        let range_max_minus_one =
            builder.constant_extension(F::Extension::from_canonical_usize((1 << LIMB_BITS) - 1));
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
    use crate::starks::{
        common::{
            ctl_values::set_ctl_values_target,
            prover::prove,
            utils::tests::random_biguint,
            verifier::{recursive_verifier, verify},
        },
        curves::g1::{
            scalar_mul_ctl::{g1_generate_ctl_values, g1_scalar_mul_ctl},
            G1_LEN,
        },
        LIMB_BITS, N_LIMBS,
    };
    use ark_bn254::G1Affine;
    use ark_ff::UniformRand;
    use hashbrown::HashMap;
    use plonky2::{
        field::{extension::Extendable, goldilocks_field::GoldilocksField},
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
        timed,
        util::timing::TimingTree,
    };
    use starky::{
        config::StarkConfig, cross_table_lookup::debug_utils::check_ctls,
        recursive_verifier::set_stark_proof_target,
    };

    use super::{G1ScalarMulInput, G1ScalarMulStark};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn g1_scalar_mul() {
        let mut rng = rand::thread_rng();
        let num_inputs = 1 << 7;
        env_logger::init();

        let inputs = (0..num_inputs)
            .map(|timestamp| {
                let input = G1ScalarMulInput {
                    s: random_biguint(&mut rng),
                    x: G1Affine::rand(&mut rng),
                    offset: G1Affine::rand(&mut rng),
                };
                (input, timestamp)
            })
            .collect::<Vec<_>>();
        let stark = G1ScalarMulStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let trace = stark.generate_trace(&inputs, 1 << LIMB_BITS);

        let mut timing = TimingTree::default();
        let cross_table_lookups = g1_scalar_mul_ctl();
        let proof = timed!(
            timing,
            "stark prove",
            prove::<F, C, _, D>(
                &stark,
                &config,
                &trace,
                &cross_table_lookups,
                &[],
                &mut timing,
            )
            .unwrap()
        );
        let ctl_values = g1_generate_ctl_values::<F>(&inputs);
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
        let circuit_proof = timed!(timing, "circuit prove", circuit.prove(pw).unwrap());
        circuit.verify(circuit_proof).unwrap();

        timing.print();
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
