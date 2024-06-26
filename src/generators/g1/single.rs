use ark_bn254::G1Affine;
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

use crate::curves::g1::G1Target;

use super::G1ScalarMulInputTarget;

#[derive(Clone, Debug)]
pub(crate) struct G1SingleGenerator<F: RichField + Extendable<D>, const D: usize> {
    pub(crate) input: G1ScalarMulInputTarget<F, D>,
    pub(crate) output: G1Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for G1SingleGenerator<F, D>
{
    fn id(&self) -> String {
        "G1SingleGenerator".to_string()
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
        let output: G1Affine = (input.x.mul_bigint(input.s.to_u64_digits()) + input.offset).into();
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
