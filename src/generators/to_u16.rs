use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    curves::{g1::G1Target, g2::G2Target},
    fields::{biguint::BigUintTarget, fq::FqTarget, fq2::Fq2Target},
};

pub trait ToU16<F: RichField + Extendable<D>, const D: usize> {
    /// Convert the `self` to u16 limbs target
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target>;
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for BigUintTarget {
    /// Convert the `self` to u16 limbs target
    /// Assumes that `self` is 8 limbs of 32bit.
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        let limbs_u16 = self
            .limbs
            .iter()
            .flat_map(|limb| {
                let (lo, hi) = builder.split_low_high(limb.0, 16, 32);
                vec![lo, hi]
            })
            .collect::<Vec<_>>();
        assert_eq!(limbs_u16.len(), 16, "Invalid length");
        limbs_u16
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for FqTarget<F, D> {
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        self.value().to_u16(builder)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for Fq2Target<F, D> {
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        self.c0
            .to_u16(builder)
            .into_iter()
            .chain(self.c1.to_u16(builder))
            .collect()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for G1Target<F, D> {
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        self.x
            .to_u16(builder)
            .into_iter()
            .chain(self.y.to_u16(builder))
            .collect()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToU16<F, D> for G2Target<F, D> {
    fn to_u16(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        self.x
            .to_u16(builder)
            .into_iter()
            .chain(self.y.to_u16(builder))
            .collect()
    }
}
