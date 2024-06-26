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
    curves::g2::G2Target, fields::biguint::BigUintTarget,
    starks::curves::g2::scalar_mul_stark::G2ScalarMulInput,
};

use super::to_u16::ToU16;

pub mod random;
pub mod single;
pub mod stark_proof;
#[derive(Clone, Debug)]
pub struct G2ScalarMulInputTarget<F: RichField + Extendable<D>, const D: usize> {
    pub s: BigUintTarget,
    pub x: G2Target<F, D>,
    pub offset: G2Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> G2ScalarMulInputTarget<F, D> {
    pub fn set_witness<W: WitnessWrite<F>>(&self, witness: &mut W, value: &G2ScalarMulInput) {
        self.s.set_witness(witness, &value.s);
        self.x.set_witness(witness, &value.x);
        self.offset.set_witness(witness, &value.offset);
    }

    pub fn get_witness<W: Witness<F>>(&self, witness: &W) -> G2ScalarMulInput {
        let s = self.s.get_witness(witness);
        let x = self.x.get_witness(witness);
        let offset = self.offset.get_witness(witness);
        G2ScalarMulInput { s, x, offset }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for G2ScalarMulInputTarget<F, D> {
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        self.x
            .to_u16(builder)
            .into_iter()
            .chain(self.offset.to_u16(builder))
            .chain(self.s.to_u16(builder))
            .collect()
    }
}
