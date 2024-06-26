use ark_bn254::Fq;
use ark_ff::Field as _;
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

use crate::fields::fq::FqTarget;

use super::FqExpInputTarget;

#[derive(Clone, Debug)]
pub(crate) struct FqSingleGenerator<F: RichField + Extendable<D>, const D: usize> {
    pub(crate) input: FqExpInputTarget<F, D>,
    pub(crate) output: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for FqSingleGenerator<F, D>
{
    fn id(&self) -> String {
        "FqSingleGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.input
            .x
            .to_vec()
            .into_iter()
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
        let output: Fq = input.x.pow(input.s.to_u64_digits());
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
