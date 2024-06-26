use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    fields::{biguint::BigUintTarget, fq::FqTarget},
    starks::fields::exp_stark::FqExpInput,
};

use super::to_u16::ToU16;

pub mod single;
pub mod stark_proof;

#[derive(Clone, Debug)]
pub struct FqExpInputTarget<F: RichField + Extendable<D>, const D: usize> {
    pub s: BigUintTarget,
    pub x: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> FqExpInputTarget<F, D> {
    pub fn set_witness<W: WitnessWrite<F>>(&self, witness: &mut W, value: &FqExpInput) {
        self.s.set_witness(witness, &value.s);
        self.x.set_witness(witness, &value.x);
    }

    pub fn get_witness<W: Witness<F>>(&self, witness: &W) -> FqExpInput {
        let s = self.s.get_witness(witness);
        let x = self.x.get_witness(witness);
        FqExpInput { s, x }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for FqExpInputTarget<F, D> {
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        self.x
            .to_u16(builder)
            .into_iter()
            .chain(self.s.to_u16(builder))
            .collect()
    }
}
