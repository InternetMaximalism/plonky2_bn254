/*
The MIT License (MIT)

Copyright (c) 2022 The Plonky2 Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Original source: https://github.com/0xPolygonZero/plonky2-ecdsa
modified by qope
*/

use core::marker::PhantomData;

use num::{BigUint, Integer, Zero};
use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField},
    },
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_u32::gadgets::{
    arithmetic_u32::{CircuitBuilderU32, U32Target},
    multiple_comparison::list_le_u32_circuit,
};

#[derive(Clone, Debug)]
pub struct BigUintTarget {
    pub limbs: Vec<U32Target>,
}

impl BigUintTarget {
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    pub fn get_limb(&self, i: usize) -> U32Target {
        self.limbs[i]
    }
}

pub trait CircuitBuilderBiguint<F: RichField + Extendable<D>, const D: usize> {
    fn constant_biguint(&mut self, value: &BigUint) -> BigUintTarget;

    fn zero_biguint(&mut self) -> BigUintTarget;

    fn connect_biguint(&mut self, lhs: &BigUintTarget, rhs: &BigUintTarget);

    fn pad_biguints(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget);

    fn cmp_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget;

    fn add_virtual_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget;

    /// Add two `BigUintTarget`s.
    fn add_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    /// Subtract two `BigUintTarget`s. We assume that the first is larger than
    /// the second.
    fn sub_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    fn mul_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    fn mul_biguint_by_bool(&mut self, a: &BigUintTarget, b: BoolTarget) -> BigUintTarget;

    /// Returns x * y + z. This is no more efficient than mul-then-add; it's
    /// purely for convenience (only need to call one CircuitBuilder function).
    fn mul_add_biguint(
        &mut self,
        x: &BigUintTarget,
        y: &BigUintTarget,
        z: &BigUintTarget,
    ) -> BigUintTarget;

    /// Returns (a / b, a % b).
    fn div_rem_biguint(&mut self, a: &BigUintTarget, b: &BigUint)
        -> (BigUintTarget, BigUintTarget);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderBiguint<F, D>
    for CircuitBuilder<F, D>
{
    fn constant_biguint(&mut self, value: &BigUint) -> BigUintTarget {
        let limb_values = value.to_u32_digits();
        if limb_values.is_empty() {
            return BigUintTarget {
                limbs: vec![self.zero_u32()],
            };
        }
        BigUintTarget {
            limbs: limb_values.iter().map(|&l| self.constant_u32(l)).collect(),
        }
    }

    fn zero_biguint(&mut self) -> BigUintTarget {
        self.constant_biguint(&BigUint::zero())
    }

    fn connect_biguint(&mut self, lhs: &BigUintTarget, rhs: &BigUintTarget) {
        let min_limbs = lhs.num_limbs().min(rhs.num_limbs());
        for i in 0..min_limbs {
            self.connect_u32(lhs.get_limb(i), rhs.get_limb(i));
        }

        for i in min_limbs..lhs.num_limbs() {
            self.assert_zero_u32(lhs.get_limb(i));
        }
        for i in min_limbs..rhs.num_limbs() {
            self.assert_zero_u32(rhs.get_limb(i));
        }
    }

    fn pad_biguints(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget) {
        if a.num_limbs() > b.num_limbs() {
            let mut padded_b = b.clone();
            for _ in b.num_limbs()..a.num_limbs() {
                padded_b.limbs.push(self.zero_u32());
            }

            (a.clone(), padded_b)
        } else {
            let mut padded_a = a.clone();
            for _ in a.num_limbs()..b.num_limbs() {
                padded_a.limbs.push(self.zero_u32());
            }

            (padded_a, b.clone())
        }
    }

    fn cmp_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget {
        let (a, b) = self.pad_biguints(a, b);

        list_le_u32_circuit(self, a.limbs, b.limbs)
    }

    fn add_virtual_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget {
        let limbs = self.add_virtual_u32_targets(num_limbs);

        BigUintTarget { limbs }
    }

    fn add_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let num_limbs = a.num_limbs().max(b.num_limbs());

        let mut combined_limbs = vec![];
        let mut carry = self.zero_u32();
        for i in 0..num_limbs {
            let a_limb = (i < a.num_limbs())
                .then(|| a.limbs[i])
                .unwrap_or_else(|| self.zero_u32());
            let b_limb = (i < b.num_limbs())
                .then(|| b.limbs[i])
                .unwrap_or_else(|| self.zero_u32());

            let (new_limb, new_carry) = self.add_many_u32(&[carry, a_limb, b_limb]);
            carry = new_carry;
            combined_limbs.push(new_limb);
        }
        combined_limbs.push(carry);

        BigUintTarget {
            limbs: combined_limbs,
        }
    }

    fn sub_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let (a, b) = self.pad_biguints(a, b);
        let num_limbs = a.limbs.len();

        let mut result_limbs = vec![];

        let mut borrow = self.zero_u32();
        for i in 0..num_limbs {
            let (result, new_borrow) = self.sub_u32(a.limbs[i], b.limbs[i], borrow);
            result_limbs.push(result);
            borrow = new_borrow;
        }
        // Borrow should be zero here.
        self.assert_zero(borrow.0);

        BigUintTarget {
            limbs: result_limbs,
        }
    }

    fn mul_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let total_limbs = a.limbs.len() + b.limbs.len();

        let mut to_add = vec![vec![]; total_limbs];
        for i in 0..a.limbs.len() {
            for j in 0..b.limbs.len() {
                let (product, carry) = self.mul_u32(a.limbs[i], b.limbs[j]);
                to_add[i + j].push(product);
                to_add[i + j + 1].push(carry);
            }
        }

        let mut combined_limbs = vec![];
        let mut carry = self.zero_u32();
        for summands in &mut to_add {
            let (new_result, new_carry) = self.add_u32s_with_carry(summands, carry);
            combined_limbs.push(new_result);
            carry = new_carry;
        }
        combined_limbs.push(carry);

        BigUintTarget {
            limbs: combined_limbs,
        }
    }

    fn mul_biguint_by_bool(&mut self, a: &BigUintTarget, b: BoolTarget) -> BigUintTarget {
        let t = b.target;

        BigUintTarget {
            limbs: a
                .limbs
                .iter()
                .map(|&l| U32Target(self.mul(l.0, t)))
                .collect(),
        }
    }

    fn mul_add_biguint(
        &mut self,
        x: &BigUintTarget,
        y: &BigUintTarget,
        z: &BigUintTarget,
    ) -> BigUintTarget {
        let prod = self.mul_biguint(x, y);
        self.add_biguint(&prod, z)
    }

    fn div_rem_biguint(
        &mut self,
        a: &BigUintTarget,
        b: &BigUint,
    ) -> (BigUintTarget, BigUintTarget) {
        let b_minus_one = self.constant_biguint(&(b - 1u32));
        let b = self.constant_biguint(b);
        let a_len = a.limbs.len();
        let b_len = b.limbs.len();
        let div_num_limbs = if b_len > a_len + 1 {
            0
        } else {
            a_len - b_len + 1
        };
        let div = self.add_virtual_biguint_target(div_num_limbs);
        let rem = self.add_virtual_biguint_target(b_len);

        self.add_simple_generator(BigUintDivRemGenerator::<F, D> {
            a: a.clone(),
            b: b.clone(),
            div: div.clone(),
            rem: rem.clone(),
            _phantom: PhantomData,
        });

        let div_b = self.mul_biguint(&div, &b);
        let div_b_plus_rem = self.add_biguint(&div_b, &rem);
        self.connect_biguint(a, &div_b_plus_rem);

        let cmp_rem_b = self.cmp_biguint(&rem, &b_minus_one);
        self.assert_one(cmp_rem_b.target);

        (div, rem)
    }
}

impl BigUintTarget {
    pub fn get_witness<F: PrimeField, W: Witness<F>>(&self, witness: &W) -> BigUint {
        self.limbs.iter().rev().fold(BigUint::zero(), |acc, limb| {
            (acc << 32) + witness.get_target(limb.0).to_canonical_biguint()
        })
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &BigUint) {
        let mut limbs = value.to_u32_digits();
        assert!(self.num_limbs() >= limbs.len());
        limbs.resize(self.num_limbs(), 0);
        for i in 0..self.num_limbs() {
            witness.set_target(self.limbs[i].0, F::from_canonical_u32(limbs[i]));
        }
    }
}

#[derive(Debug)]
struct BigUintDivRemGenerator<F: RichField + Extendable<D>, const D: usize> {
    a: BigUintTarget,
    b: BigUintTarget,
    div: BigUintTarget,
    rem: BigUintTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for BigUintDivRemGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        self.a
            .limbs
            .iter()
            .chain(&self.b.limbs)
            .map(|&l| l.0)
            .collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let a = self.a.get_witness(witness);
        let b = self.b.get_witness(witness);
        let (div, rem) = a.div_rem(&b);

        self.div.set_witness(out_buffer, &div);
        self.rem.set_witness(out_buffer, &rem);
    }

    fn id(&self) -> String {
        unimplemented!()
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        unimplemented!()
    }

    fn deserialize(
        _src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num::{BigUint, FromPrimitive, Integer};
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{rngs::OsRng, Rng};

    use super::*;

    #[test]
    fn test_biguint_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let x_value = BigUint::from_u128(rng.gen()).unwrap();
        let y_value = BigUint::from_u128(rng.gen()).unwrap();
        let expected_z_value = &x_value + &y_value;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
        let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());
        let z = builder.add_biguint(&x, &y);
        let expected_z = builder.add_virtual_biguint_target(expected_z_value.to_u32_digits().len());
        builder.connect_biguint(&z, &expected_z);

        x.set_witness(&mut pw, &x_value);
        y.set_witness(&mut pw, &y_value);
        expected_z.set_witness(&mut pw, &expected_z_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_sub() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let mut x_value = BigUint::from_u128(rng.gen()).unwrap();
        let mut y_value = BigUint::from_u128(rng.gen()).unwrap();
        if y_value > x_value {
            (x_value, y_value) = (y_value, x_value);
        }
        let expected_z_value = &x_value - &y_value;

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_biguint(&x_value);
        let y = builder.constant_biguint(&y_value);
        let z = builder.sub_biguint(&x, &y);
        let expected_z = builder.constant_biguint(&expected_z_value);

        builder.connect_biguint(&z, &expected_z);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_mul() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let x_value = BigUint::from_u128(rng.gen()).unwrap();
        let y_value = BigUint::from_u128(rng.gen()).unwrap();
        let expected_z_value = &x_value * &y_value;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
        let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());
        let z = builder.mul_biguint(&x, &y);
        let expected_z = builder.add_virtual_biguint_target(expected_z_value.to_u32_digits().len());
        builder.connect_biguint(&z, &expected_z);

        x.set_witness(&mut pw, &x_value);
        y.set_witness(&mut pw, &y_value);
        expected_z.set_witness(&mut pw, &expected_z_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_cmp() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let x_value = BigUint::from_u128(rng.gen()).unwrap();
        let y_value = BigUint::from_u128(rng.gen()).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_biguint(&x_value);
        let y = builder.constant_biguint(&y_value);
        let cmp = builder.cmp_biguint(&x, &y);
        let expected_cmp = builder.constant_bool(x_value <= y_value);

        builder.connect(cmp.target, expected_cmp.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_div_rem() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let mut x_value = BigUint::from_u128(rng.gen()).unwrap();
        let mut y_value = BigUint::from_u128(rng.gen()).unwrap();
        if y_value > x_value {
            (x_value, y_value) = (y_value, x_value);
        }
        let (expected_div_value, expected_rem_value) = x_value.div_rem(&y_value);

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_biguint(&x_value);
        let (div, rem) = builder.div_rem_biguint(&x, &y_value);

        let expected_div = builder.constant_biguint(&expected_div_value);
        let expected_rem = builder.constant_biguint(&expected_rem_value);

        builder.connect_biguint(&div, &expected_div);
        builder.connect_biguint(&rem, &expected_rem);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
