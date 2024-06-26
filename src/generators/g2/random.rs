use crate::curves::g2::G2Target;
use ark_bn254::G2Affine;
use ark_ff::UniformRand;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::PartitionWitness,
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData},
};

/// A generator that produces a random G2 element
#[derive(Clone, Debug)]
pub(crate) struct G2RandomGenerator<F: RichField + Extendable<D>, const D: usize> {
    pub(crate) target: G2Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for G2RandomGenerator<F, D>
{
    fn id(&self) -> String {
        "G2RandomGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        Vec::new()
    }

    fn run_once(&self, _pw: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let random = G2Affine::rand(&mut rand::thread_rng());
        self.target.set_witness(out_buffer, &random);
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        unimplemented!()
    }

    fn deserialize(
        _src: &mut plonky2::util::serialization::Buffer,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self> {
        unimplemented!()
    }
}

/// Set a random G2 element to `target`
pub fn set_random_g2<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target: &G2Target<F, D>,
) {
    let generator = G2RandomGenerator {
        target: target.clone(),
    };
    builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
        generator.adapter(),
    )]);
}
