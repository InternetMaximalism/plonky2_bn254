use std::marker::PhantomData;

use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
use num::BigUint;
use plonky2::{
    field::{extension::Extendable, polynomial::PolynomialValues},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
};
use starky::{evaluation_frame::StarkFrame, stark::Stark, util::trace_rows_to_poly_values};

use crate::starks::curves::{
    common::{round_flags::generate_round_flags, utils::biguint_to_le_bits},
    g1::scalar_mul_view::N_BITS,
};

use super::{
    add::{generate_g1_add, G1AddAux},
    scalar_mul_view::{G1ScalarMulView, G1_SCALAR_MUL_VIEW_LEN},
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
        let num_rows = min_rows.max(inputs.len()).next_power_of_two();
        let mut rows = vec![];
        for input in inputs {
            rows.extend(self.generate_one_set(input));
        }
        let default_row = [F::default(); G1_SCALAR_MUL_VIEW_LEN];
        rows.resize(num_rows, default_row);
        // todo: generate range checks
        trace_rows_to_poly_values(rows)
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
        let (sum, sum_aux) = if s_bits[0] {
            generate_g1_add(x.into(), offset.into())
        } else {
            (offset.into(), G1AddAux::default())
        };
        let bits: [F; N_BITS] = s_bits
            .into_iter()
            .map(F::from_bool)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let bit_filtered = bits[0];
        G1ScalarMulView {
            double: x.into(),
            double_aux: G1AddAux::default(),
            sum,
            sum_aux,
            bits,
            bit_filtered,
            timestamp,
            round_flags,
            filter: F::default(),
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
        let (sum, sum_aux) = if cur_bit.is_one() {
            generate_g1_add(local.sum, double)
        } else {
            (local.sum, G1AddAux::default())
        };
        let timestamp = local.timestamp;
        let round_flags = generate_round_flags(row_index, N_BITS);
        let bit_filtered = bits[0];
        G1ScalarMulView {
            double,
            double_aux,
            sum,
            sum_aux,
            bits,
            bit_filtered,
            timestamp,
            round_flags,
            filter: F::default(),
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
        todo!()
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut starky::constraint_consumer::RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn requires_ctls(&self) -> bool {
        true
    }
}
