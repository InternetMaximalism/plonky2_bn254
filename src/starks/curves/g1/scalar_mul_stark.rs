use std::marker::PhantomData;

use plonky2::{
    field::{extension::Extendable, polynomial::PolynomialValues},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
};
use starky::{evaluation_frame::StarkFrame, stark::Stark};

use super::scalar_mul_view::{G1ScalarMulView, G1_SCALAR_MUL_VIEW_LEN};

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

    pub(crate) fn generate_trace(&self) -> Vec<PolynomialValues<F>> {
        todo!()
    }

    fn generate_one_set(&self) -> Vec<[F; G1_SCALAR_MUL_VIEW_LEN]> {
        todo!()
    }

    fn generate_first_row(&self) -> G1ScalarMulView<F> {
        todo!()
    }

    fn generate_transition(&self, local: &G1ScalarMulView<F>) -> G1ScalarMulView<F> {
        todo!()
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
