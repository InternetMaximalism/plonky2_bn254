use ark_bn254::G2Affine;
use ark_ec::AffineRepr as _;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::PartitionWitness,
    },
    plonk::circuit_data::CommonCircuitData,
};

use crate::curves::g2::G2Target;

use super::G2ScalarMulInputTarget;

#[derive(Clone, Debug)]
pub(crate) struct G2SingleGenerator<F: RichField + Extendable<D>, const D: usize> {
    pub(crate) input: G2ScalarMulInputTarget<F, D>,
    pub(crate) output: G2Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for G2SingleGenerator<F, D>
{
    fn id(&self) -> String {
        "G2SingleGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.input
            .x
            .to_vec()
            .into_iter()
            .chain(self.input.offset.to_vec())
            .chain(
                self.input
                    .s
                    .limbs
                    .iter()
                    .map(|limb| limb.0)
                    .collect::<Vec<_>>(),
            )
            .collect()
    }

    fn run_once(&self, pw: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let input = self.input.get_witness(pw);
        let output: G2Affine = (input.x.mul_bigint(input.s.to_u64_digits()) + input.offset).into();
        self.output.set_witness(out_buffer, &output);
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
