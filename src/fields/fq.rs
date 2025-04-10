use crate::builder::BuilderBn254Stark as _;

use super::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    sgn::Sgn as _,
};
use ark_bn254::Fq;
use ark_ff::Field;
use num::{BigUint, Zero};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::serialization::Buffer,
};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

#[derive(Clone, Debug)]
pub struct FqTarget<F: RichField + Extendable<D>, const D: usize> {
    value: BigUintTarget,
    mod_taken: bool, // Whether the value is already taken the modulus
    _maker: std::marker::PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> FqTarget<F, D> {
    pub fn modulus(&self) -> BigUint {
        BigUint::from(Fq::from(-1)) + 1u32
    }

    fn modulus_target(&self, builder: &mut CircuitBuilder<F, D>) -> BigUintTarget {
        builder.constant_biguint(&self.modulus())
    }

    pub fn num_modulus_limbs() -> usize {
        8
    }

    pub fn value(&self) -> BigUintTarget {
        self.value.clone()
    }

    pub fn mod_taken(&self) -> bool {
        self.mod_taken
    }

    pub fn from_value(value: &BigUintTarget, mod_taken: bool) -> Self {
        Self {
            value: value.clone(),
            mod_taken,
            _maker: std::marker::PhantomData,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        assert!(self.mod_taken);
        self.value().limbs.into_iter().map(|limb| limb.0).collect()
    }

    /// Create an element from a vector, assuming that range checks and modulus.
    pub fn from_slice(value: &[Target]) -> Self {
        let limbs = value.into_iter().map(|v| U32Target(*v)).collect();
        Self::from_value(&BigUintTarget { limbs }, true)
    }

    pub fn from_single(value: Target) -> Self {
        Self::from_slice(&[value])
    }

    pub fn zero(builder: &mut CircuitBuilder<F, D>) -> FqTarget<F, D> {
        let zero = builder.zero_u32();
        let limbs = vec![zero; Self::num_modulus_limbs()];
        let value = BigUintTarget { limbs };
        Self::from_value(&value, true)
    }

    pub fn one(builder: &mut CircuitBuilder<F, D>) -> FqTarget<F, D> {
        let mut one = Self::zero(builder);
        one.value.limbs[0] = builder.one_u32();
        one
    }

    /// Create a new element without limb range checks and the modulus range
    /// check.
    pub fn new_unchecked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let value = builder.add_virtual_biguint_target(Self::num_modulus_limbs());
        Self::from_value(&value, true)
    }

    /// Same as `new_unchecked` but with limb range checks and the modulus range
    /// check
    pub fn new_checked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = Self::new_unchecked(builder);
        for limb in x.value().limbs.iter() {
            builder.range_check(limb.0, 32);
        }
        let is_valid = x.is_valid(builder);
        builder.assert_one(is_valid.target);
        x
    }

    pub fn is_valid(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let modulus_minus_one = Self::constant(builder, &Fq::from(-1));
        builder.cmp_biguint(&self.value(), &modulus_minus_one.value())
    }

    /// Assert the two values are equal.
    pub fn connect(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) {
        let a = self.take_mod(builder);
        let b = other.take_mod(builder);
        builder.connect_biguint(&a.value(), &b.value());
    }

    /// Set the witness value
    pub fn set_witness<W: WitnessWrite<F>>(&self, witness: &mut W, value: &Fq) {
        assert!(self.mod_taken);
        self.value.set_witness(witness, &BigUint::from(*value));
    }

    pub fn get_witness<W: Witness<F>>(&self, witness: &W) -> Fq {
        self.value().get_witness(witness).into()
    }

    /// Create a constant element with padding
    pub fn constant(builder: &mut CircuitBuilder<F, D>, value: &Fq) -> Self {
        let value = BigUint::from(*value);
        assert!(value.to_u32_digits().len() <= Self::num_modulus_limbs());
        let value = builder.constant_biguint(&value);
        Self::from_value(&value, true).pad(builder)
    }

    fn pad(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let value = self.value();
        let mut limbs = value.limbs;
        assert!(limbs.len() <= Self::num_modulus_limbs());
        let zero = builder.zero_u32();
        limbs.resize(Self::num_modulus_limbs(), zero);
        let padded_value = BigUintTarget { limbs };
        Self::from_value(&padded_value, self.mod_taken)
    }

    /// Returns the remainder divided by the modulus
    pub fn take_mod(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        if self.mod_taken {
            return self.clone();
        }
        let (_div, rem) = builder.div_rem_biguint(&self.value(), &self.modulus());
        Self::from_value(&rem, true).pad(builder)
    }

    /// Add two elements without taking the modulus
    pub fn add(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        Self::from_value(&builder.add_biguint(&self.value(), &other.value()), false)
    }

    /// Take the negative as an element of the field
    pub fn neg(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let x_mod = self.take_mod(builder);
        let modulus = self.modulus_target(builder);
        Self::from_value(&builder.sub_biguint(&modulus, &x_mod.value()), false)
    }

    /// Subtract two elements without taking the modulus
    pub fn sub(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        let neg_other = other.neg(builder);
        self.add(builder, &neg_other)
    }

    /// Multiply an element by a constant u32 without taking the modulus
    pub fn mul_constant_u32(&self, builder: &mut CircuitBuilder<F, D>, constant: u32) -> Self {
        let constant = builder.constant_biguint(&BigUint::from(constant));
        Self::from_value(&builder.mul_biguint(&self.value(), &constant), false)
    }

    /// Multiply two elements with taking the modulus
    pub fn mul(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        let mul = Self::from_value(&builder.mul_biguint(&self.value(), &other.value()), false);
        mul.take_mod(builder)
    }

    pub fn is_equal(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> BoolTarget {
        let a = self.take_mod(builder);
        let b = other.take_mod(builder);
        let is_equal =
            a.value
                .limbs
                .into_iter()
                .zip(b.value.limbs)
                .fold(builder.one(), |acc, (a, b)| {
                    let is_equal = builder.is_equal(a.0, b.0);
                    builder.mul(acc, is_equal.target)
                });
        BoolTarget::new_unsafe(is_equal)
    }

    /// Returns whether the element is zero
    pub fn is_zero(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let limbs = self.take_mod(builder).to_vec();
        let zero = builder.zero();
        let is_zero = limbs.into_iter().fold(builder.one(), |acc, limb| {
            let is_zero = builder.is_equal(limb, zero);
            builder.mul(acc, is_zero.target)
        });
        BoolTarget::new_unsafe(is_zero)
    }

    /// If `selector` is true, return `self`, otherwise return `other`
    pub fn select(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        selector: &BoolTarget,
    ) -> Self {
        let not_selector = builder.not(*selector);
        let x = self.mul(builder, &Self::from_single(selector.target));
        let y = other.mul(builder, &Self::from_single(not_selector.target));
        x.add(builder, &y).take_mod(builder)
    }

    /// Connect `self` and `other` only if `flag` is true.
    pub fn connect_conditional(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        flag: &BoolTarget,
    ) {
        let diff = self.sub(builder, other);
        let is_zero = diff.is_zero(builder);
        let is_not_zero = builder.not(is_zero);
        let is_not_zero_selected = builder.and(is_not_zero, *flag);
        builder.assert_zero(is_not_zero_selected.target);
    }

    /// If `self` is zero, return zero, otherwise return the inverse of `self`
    pub fn inv(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = self.take_mod(builder);
        let inv = Self::new_unchecked(builder);
        builder.add_simple_generator(FqInverseGenerator::<F, D> {
            x: x.clone(),
            inv: inv.clone(),
        });
        let is_zero = x.is_zero(builder);
        let is_not_zero = FqTarget::from_single(builder.not(is_zero).target);
        let out = inv.mul(builder, &is_not_zero); // out = inv*is_not_zero
        let x_out = x.mul(builder, &out); // x_out = x*out
        x_out.connect(builder, &is_not_zero); // x*out = 1 - is_zero
        out.take_mod(builder)
    }

    /// Returns the sign of the element
    /// even is false, odd is true
    pub fn sgn(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let moded = self.take_mod(builder);
        let first_digit = moded.value().limbs[0].0;
        let bits = builder.split_le(first_digit, 32);
        bits[0]
    }

    /// If a square root exists for `self``, return a square root with the sign
    /// specified by `sgn`.
    pub fn sqrt_with_sgn(&self, builder: &mut CircuitBuilder<F, D>, sgn: BoolTarget) -> Self {
        let x = self.take_mod(builder);
        let sqrt = Self::new_unchecked(builder);
        builder.add_simple_generator(FqSqrtGenerator::<F, D> {
            x: x.clone(),
            sgn: sgn.clone(),
            sqrt: sqrt.clone(),
        });
        let sqrt_sq = sqrt.mul(builder, &sqrt);
        sqrt_sq.connect(builder, &x); // sqrt^2 = x
        let sgn_sqrt = sqrt.sgn(builder);
        builder.connect(sgn_sqrt.target, sgn.target);
        sqrt
    }

    pub fn is_square<C: GenericConfig<D, F = F> + 'static>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let k: BigUint = (Fq::from(-1) / Fq::from(2)).into();
        let k_t = builder.constant_biguint(&k);
        let legendre = builder.fq_exp::<C>(k_t, self.clone());
        let one = Self::one(builder);
        legendre.is_equal(builder, &one)
    }
}

#[derive(Debug)]
struct FqInverseGenerator<F: RichField + Extendable<D>, const D: usize> {
    x: FqTarget<F, D>,
    inv: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for FqInverseGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        self.x.to_vec()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let x: Fq = self.x.get_witness(witness);
        let inv_x: Fq = match x.inverse() {
            Some(inv_x) => inv_x,
            None => Fq::zero(),
        };
        self.inv.set_witness(out_buffer, &inv_x.into());
    }

    fn id(&self) -> std::string::String {
        "FqInverseGenerator".to_string()
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        unimplemented!()
    }

    fn deserialize(
        _src: &mut Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

#[derive(Debug)]
struct FqSqrtGenerator<F: RichField + Extendable<D>, const D: usize> {
    x: FqTarget<F, D>,
    sgn: BoolTarget,
    sqrt: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for FqSqrtGenerator<F, D> {
    fn dependencies(&self) -> Vec<Target> {
        let mut x_vec = self.x.to_vec();
        x_vec.push(self.sgn.target);
        x_vec
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let x: Fq = self.x.get_witness(witness);
        let sgn = witness.get_target(self.sgn.target).is_one(); // convert 1 => true, 0 => false
        let mut sqrt_x: Fq = x.sqrt().unwrap(); // Sqrt of Fq always exists
        if sqrt_x.sgn() != sgn {
            sqrt_x = -sqrt_x;
        }
        self.sqrt.set_witness(out_buffer, &sqrt_x.into());
    }

    fn id(&self) -> std::string::String {
        "FqSqrtGenerator".to_string()
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        unimplemented!()
    }

    fn deserialize(
        _src: &mut Buffer,
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
    use crate::fields::biguint::CircuitBuilderBiguint;

    use super::FqTarget;
    use ark_bn254::Fq;
    use ark_ff::{Field, UniformRand};
    use num::{BigUint, Zero};
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn fq_ops() {
        let mut rng = rand::thread_rng();
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let constant = rng.gen::<u32>();

        let a_add_b = a + b;
        let neg_a = -a;
        let a_sub_b = a - b;
        let a_mul_b = a * b;
        let a_mul_constant = a * Fq::from(constant);
        let a_inv: Fq = a.inverse().unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = FqTarget::new_unchecked(&mut builder);
        let b_t = FqTarget::new_unchecked(&mut builder);

        let a_add_b_t = a_t.add(&mut builder, &b_t).take_mod(&mut builder);
        let neg_a_t = a_t.neg(&mut builder).take_mod(&mut builder);
        let a_sub_b_t = a_t.sub(&mut builder, &b_t).take_mod(&mut builder);
        let a_mul_b_t = a_t.mul(&mut builder, &b_t);
        let a_mul_constant_t = a_t
            .mul_constant_u32(&mut builder, constant)
            .take_mod(&mut builder);
        let a_inv_t = a_t.inv(&mut builder);
        let zero = FqTarget::constant(&mut builder, &Fq::zero());
        let zero_inv_t = zero.inv(&mut builder);

        let mut pw = PartialWitness::<F>::new();
        a_t.set_witness(&mut pw, &a);
        b_t.set_witness(&mut pw, &b);
        a_add_b_t.set_witness(&mut pw, &a_add_b);
        neg_a_t.set_witness(&mut pw, &neg_a);
        a_sub_b_t.set_witness(&mut pw, &a_sub_b);
        a_mul_b_t.set_witness(&mut pw, &a_mul_b);
        a_mul_constant_t.set_witness(&mut pw, &a_mul_constant);
        a_inv_t.set_witness(&mut pw, &a_inv);
        zero_inv_t.set_witness(&mut pw, &Fq::zero());
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn fq_selection() {
        let mut rng = rand::thread_rng();
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let constant = rng.gen::<u32>();

        let a_add_b = a + b;
        let neg_a = -a;
        let a_sub_b = a - b;
        let a_mul_b = a * b;
        let a_mul_constant = a * Fq::from(constant);
        let a_inv: Fq = a.inverse().unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = FqTarget::constant(&mut builder, &a.into());
        let b_t = FqTarget::constant(&mut builder, &b.into());

        let a_add_b_t = a_t.add(&mut builder, &b_t).take_mod(&mut builder);
        let neg_a_t = a_t.neg(&mut builder).take_mod(&mut builder);
        let a_sub_b_t = a_t.sub(&mut builder, &b_t).take_mod(&mut builder);
        let a_mul_b_t = a_t.mul(&mut builder, &b_t);
        let a_mul_constant_t = a_t
            .mul_constant_u32(&mut builder, constant)
            .take_mod(&mut builder);
        let a_inv_t = a_t.inv(&mut builder);
        let zero = FqTarget::constant(&mut builder, &Fq::zero());
        let zero_inv_t = zero.inv(&mut builder);

        let mut pw = PartialWitness::<F>::new();
        a_add_b_t.set_witness(&mut pw, &a_add_b);
        neg_a_t.set_witness(&mut pw, &neg_a);
        a_sub_b_t.set_witness(&mut pw, &a_sub_b);
        a_mul_b_t.set_witness(&mut pw, &a_mul_b);
        a_mul_constant_t.set_witness(&mut pw, &a_mul_constant);
        a_inv_t.set_witness(&mut pw, &a_inv);
        zero_inv_t.set_witness(&mut pw, &Fq::zero());
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn fq_is_sq() {
        let num_inputs = 100;
        let rng = &mut rand::thread_rng();
        let inputs = (0..num_inputs).map(|_| Fq::rand(rng)).collect::<Vec<_>>();
        let outputs = inputs
            .iter()
            .map(|input| input.sqrt().is_some())
            .collect::<Vec<_>>();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let inputs_t = inputs
            .iter()
            .map(|input| FqTarget::constant(&mut builder, input))
            .collect::<Vec<_>>();
        let outputs_t = inputs_t
            .iter()
            .map(|input| input.is_square::<C>(&mut builder))
            .collect::<Vec<_>>();

        let mut pw = PartialWitness::new();
        for (t, w) in outputs_t.iter().zip(outputs) {
            pw.set_bool_target(*t, w);
        }
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn fq_is_valid() {
        let a: BigUint = Fq::from(-2).into();
        let b = BigUint::from(Fq::from(-1)) + 1u32;
        let c = BigUint::from(Fq::from(-1)) + 2u32;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = FqTarget::from_value(&builder.constant_biguint(&a), false);
        let b_t = FqTarget::from_value(&builder.constant_biguint(&b), false);
        let c_t = FqTarget::from_value(&builder.constant_biguint(&c), false);

        let is_valid_a = a_t.is_valid(&mut builder);
        let is_valid_b = b_t.is_valid(&mut builder);
        let is_valid_c = c_t.is_valid(&mut builder);

        let mut pw = PartialWitness::<F>::new();
        pw.set_bool_target(is_valid_a, true);
        pw.set_bool_target(is_valid_b, false);
        pw.set_bool_target(is_valid_c, false);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
