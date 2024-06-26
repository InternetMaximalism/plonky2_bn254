use std::marker::PhantomData;

use crate::{
    curves::{g1::G1Target, g2::G2Target},
    fields::fq::FqTarget,
    generators::{fq::FqExpInputTarget, g1::G1ScalarMulInputTarget, g2::G2ScalarMulInputTarget},
};
use core::any::Any;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::builder_hook::BuilderHook,
};

#[derive(Debug)]
pub struct Bn254Hook<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub(crate) inputs_g1: Vec<G1ScalarMulInputTarget<F, D>>,
    pub(crate) outputs_g1: Vec<G1Target<F, D>>,
    pub(crate) inputs_g2: Vec<G2ScalarMulInputTarget<F, D>>,
    pub(crate) outputs_g2: Vec<G2Target<F, D>>,
    pub(crate) inputs_fq: Vec<FqExpInputTarget<F, D>>,
    pub(crate) outputs_fq: Vec<FqTarget<F, D>>,
    _maker: PhantomData<C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Bn254Hook<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        Self {
            inputs_g1: vec![],
            outputs_g1: vec![],
            inputs_g2: vec![],
            outputs_g2: vec![],
            inputs_fq: vec![],
            outputs_fq: vec![],
            _maker: PhantomData,
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    BuilderHook<F, D> for Bn254Hook<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn constrain(&self, builder: &mut CircuitBuilder<F, D>) {
        use crate::generators::{
            fq::stark_proof::FqStarkProofGenerator, g1::stark_proof::G1StarkProofGenerator,
            g2::stark_proof::G2StarkProofGenerator,
        };
        use plonky2::iop::generator::SimpleGenerator as _;

        if !self.inputs_g1.is_empty() {
            let generator = G1StarkProofGenerator::<F, C, D>::new(builder, &self.inputs_g1);
            for (x, y) in self.outputs_g1.iter().zip(generator.outputs.iter()) {
                x.connect(builder, y);
            }
            builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
                generator.adapter(),
            )]);
        }
        if !self.inputs_g2.is_empty() {
            let generator = G2StarkProofGenerator::<F, C, D>::new(builder, &self.inputs_g2);
            for (x, y) in self.outputs_g2.iter().zip(generator.outputs.iter()) {
                x.connect(builder, y);
            }
            builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
                generator.adapter(),
            )]);
        }
        if !self.inputs_fq.is_empty() {
            let generator = FqStarkProofGenerator::<F, C, D>::new(builder, &self.inputs_fq);
            for (x, y) in self.outputs_fq.iter().zip(generator.outputs.iter()) {
                x.connect(builder, y);
            }
            builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
                generator.adapter(),
            )]);
        }
    }

    #[cfg(feature = "not-constrain-bn254-stark")]
    fn constrain(&self, _builder: &mut CircuitBuilder<F, D>) {}

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
