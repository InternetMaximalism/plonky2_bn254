use ark_bn254::Fq2;
use ark_ff::Field as _;
use num::Zero;
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

use super::{fq::FqTarget, sgn::Sgn};

#[derive(Clone, Debug)]
pub struct Fq2Target<F: RichField + Extendable<D>, const D: usize> {
    pub c0: FqTarget<F, D>,
    pub c1: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> Fq2Target<F, D> {
    pub fn from_value(c0: &FqTarget<F, D>, c1: &FqTarget<F, D>) -> Self {
        Self {
            c0: c0.clone(),
            c1: c1.clone(),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        self.c0
            .to_vec()
            .into_iter()
            .chain(self.c1.to_vec().into_iter())
            .collect()
    }

    pub fn from_slice(value: &[Target]) -> Self {
        let num_limbs = FqTarget::<F, D>::num_modulus_limbs();
        assert!(value.len() == 2 * num_limbs);
        let c0 = FqTarget::from_slice(&value[0..num_limbs]);
        let c1 = FqTarget::from_slice(&value[num_limbs..]);
        Self::from_value(&c0, &c1)
    }

    pub fn from_single(value: Target) -> Self {
        let c0 = FqTarget::from_single(value);
        let c1 = FqTarget::from_slice(&[]);
        Self::from_value(&c0, &c1)
    }

    /// Assert the two values are equal.
    pub fn connect(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) {
        self.c0.connect(builder, &other.c0);
        self.c1.connect(builder, &other.c1);
    }

    pub fn connect_conditional(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        flag: &BoolTarget,
    ) {
        self.c0.connect_conditional(builder, &other.c0, flag);
        self.c1.connect_conditional(builder, &other.c1, flag);
    }

    pub fn select(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        selector: &BoolTarget,
    ) -> Self {
        let c0 = self.c0.select(builder, &other.c0, selector);
        let c1 = self.c1.select(builder, &other.c1, selector);
        Self::from_value(&c0, &c1)
    }

    pub fn set_witness<W: WitnessWrite<F>>(&self, witness: &mut W, value: &Fq2) {
        self.c0.set_witness(witness, &value.c0);
        self.c1.set_witness(witness, &value.c1);
    }

    pub fn get_witness<W: Witness<F>>(&self, witness: &W) -> Fq2 {
        let c0 = self.c0.get_witness(witness);
        let c1 = self.c1.get_witness(witness);
        Fq2::new(c0, c1)
    }

    pub fn new_unchecked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let c0 = FqTarget::new_unchecked(builder);
        let c1 = FqTarget::new_unchecked(builder);
        Self::from_value(&c0, &c1)
    }

    /// Same as `new_unchecked` but with limb range checks and the modulus range
    /// check
    pub fn new_checked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let c0 = FqTarget::new_checked(builder);
        let c1 = FqTarget::new_checked(builder);
        Self::from_value(&c0, &c1)
    }

    pub fn is_valid(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let c0_is_valid = self.c0.is_valid(builder);
        let c1_is_valid = self.c1.is_valid(builder);
        builder.and(c0_is_valid, c1_is_valid)
    }

    /// Create a constant element with padding
    pub fn constant(builder: &mut CircuitBuilder<F, D>, value: &Fq2) -> Self {
        let c0 = FqTarget::constant(builder, &value.c0);
        let c1 = FqTarget::constant(builder, &value.c1);
        Self::from_value(&c0, &c1)
    }

    /// Returns the remainder divided by the modulus
    pub fn take_mod(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let c0_mod = self.c0.take_mod(builder);
        let c1_mod = self.c1.take_mod(builder);
        Self::from_value(&c0_mod, &c1_mod)
    }

    /// Add two elements without taking the modulus
    pub fn add(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        let c0 = self.c0.add(builder, &other.c0);
        let c1 = self.c1.add(builder, &other.c1);
        Self::from_value(&c0, &c1)
    }

    /// Take the negative as an element of the field
    pub fn neg(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let c0_neg = self.c0.neg(builder);
        let c1_neg = self.c1.neg(builder);
        Self::from_value(&c0_neg, &c1_neg)
    }

    /// Subtract two elements without taking the modulus
    pub fn sub(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        let c0_sub = self.c0.sub(builder, &other.c0);
        let c1_sub = self.c1.sub(builder, &other.c1);
        Self::from_value(&c0_sub, &c1_sub)
    }

    /// Multiply an element by a constant u32 without taking the modulus
    pub fn mul_constant_u32(&self, builder: &mut CircuitBuilder<F, D>, constant: u32) -> Self {
        let c0_mul = self.c0.mul_constant_u32(builder, constant);
        let c1_mul = self.c1.mul_constant_u32(builder, constant);
        Self::from_value(&c0_mul, &c1_mul)
    }

    /// Multiply two elements without taking the modulus
    pub fn mul(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        let c00 = self.c0.mul(builder, &other.c0);
        let c11 = self.c1.mul(builder, &other.c1);
        let c10 = self.c1.mul(builder, &other.c0);
        let c01 = self.c0.mul(builder, &other.c1);
        let c0 = c00.sub(builder, &c11);
        let c1 = c10.add(builder, &c01);
        Self::from_value(&c0, &c1)
    }

    pub fn is_equal(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> BoolTarget {
        let c0_is_equal = self.c0.is_equal(builder, &other.c0);
        let c1_is_equal = self.c1.is_equal(builder, &other.c1);
        builder.and(c0_is_equal, c1_is_equal)
    }

    pub fn is_zero(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let c0_is_zero = self.c0.is_zero(builder);
        let c1_is_zero = self.c1.is_zero(builder);
        builder.and(c0_is_zero, c1_is_zero)
    }

    /// Returns the sign of the element
    /// even is false, odd is true
    pub fn sgn(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let sgn_x = self.c0.sgn(builder);
        let is_zero = self.c0.is_zero(builder);
        let sgn_y = self.c1.sgn(builder);
        let is_zero_and_sgn_y = builder.and(is_zero, sgn_y.clone());
        builder.or(sgn_x, is_zero_and_sgn_y)
    }

    /// If `self` is zero, return zero, otherwise return the inverse of `self`
    pub fn inv(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = self.take_mod(builder);
        let inv = Self::new_unchecked(builder);
        builder.add_simple_generator(Fq2InverseGenerator::<F, D> {
            x: x.clone(),
            inv: inv.clone(),
        });
        let is_zero = x.is_zero(builder);
        let is_not_zero = Fq2Target::from_single(builder.not(is_zero).target);
        let out = inv.mul(builder, &is_not_zero); // out = inv*is_not_zero
        let x_out = x.mul(builder, &out); // x_out = x*out
        x_out.connect(builder, &is_not_zero); // x*out = 1 - is_zero
        out.take_mod(builder)
    }

    /// If a square root exists for `self``, return a square root with the sign
    /// specified by `sgn`. If a square root does not exist, the proof
    /// cannot be generated.
    pub fn sqrt_with_sgn(&self, builder: &mut CircuitBuilder<F, D>, sgn: BoolTarget) -> Self {
        let x = self.take_mod(builder);
        let sqrt = Self::new_unchecked(builder);
        builder.add_simple_generator(Fq2SqrtGenerator::<F, D> {
            x: x.clone(),
            sgn: sgn.clone(),
            sqrt: sqrt.clone(),
        });

        // sqrt^2 = x
        let sqrt_sq = sqrt.mul(builder, &sqrt);
        sqrt_sq.connect(builder, &x);

        // sgn(sqrt) = sgn(sgn)
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
        let x = self.c0.clone();
        let y = self.c1.clone();
        let x_sq = x.mul(builder, &x);
        let y_sq = y.mul(builder, &y);
        let norm = x_sq.add(builder, &y_sq).take_mod(builder);
        norm.is_square::<C>(builder)
    }
}

#[derive(Debug)]
struct Fq2InverseGenerator<F: RichField + Extendable<D>, const D: usize> {
    x: Fq2Target<F, D>,
    inv: Fq2Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for Fq2InverseGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        self.x.to_vec()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let x = self.x.get_witness(witness);
        let inv_x: Fq2 = match x.inverse() {
            Some(inv_x) => inv_x,
            None => Fq2::zero(),
        };
        self.inv.set_witness(out_buffer, &inv_x);
    }

    fn id(&self) -> std::string::String {
        "Fq2InverseGenerator".to_string()
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
struct Fq2SqrtGenerator<F: RichField + Extendable<D>, const D: usize> {
    x: Fq2Target<F, D>,
    sgn: BoolTarget,
    sqrt: Fq2Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for Fq2SqrtGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        let mut x_vec = self.x.to_vec();
        x_vec.push(self.sgn.target);
        x_vec
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let x = self.x.get_witness(witness);
        let sgn = witness.get_target(self.sgn.target).is_one(); // convert 1 => true, 0 => false
        let mut sqrt_x: Fq2 = x.sqrt().expect("Fq2 sqrt failed");
        if sqrt_x.sgn() != sgn {
            sqrt_x = -sqrt_x;
        }
        self.sqrt.set_witness(out_buffer, &sqrt_x);
    }

    fn id(&self) -> std::string::String {
        "Fq2SqrtGenerator".to_string()
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
    use crate::fields::sgn::Sgn;

    use super::Fq2Target;
    use ark_bn254::Fq2;
    use ark_ff::{Field, UniformRand};
    use num::Zero;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
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
    fn fq2_ops() {
        let mut rng = rand::thread_rng();
        let a = Fq2::rand(&mut rng);
        let b = Fq2::rand(&mut rng);
        let constant = rng.gen::<u32>();

        let a_add_b = a + b;
        let neg_a = -a;
        let a_sub_b = a - b;
        let a_mul_b = a * b;
        let a_mul_constant = a * Fq2::from(constant);
        let a_inv: Fq2 = a.inverse().unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = Fq2Target::constant(&mut builder, &a.into());
        let b_t = Fq2Target::constant(&mut builder, &b.into());

        let a_add_b_t = a_t.add(&mut builder, &b_t).take_mod(&mut builder);
        let neg_a_t = a_t.neg(&mut builder).take_mod(&mut builder);
        let a_sub_b_t = a_t.sub(&mut builder, &b_t).take_mod(&mut builder);
        let a_mul_b_t = a_t.mul(&mut builder, &b_t).take_mod(&mut builder);
        let a_mul_constant_t = a_t
            .mul_constant_u32(&mut builder, constant)
            .take_mod(&mut builder);
        let a_inv_t = a_t.inv(&mut builder);
        let zero = Fq2Target::constant(&mut builder, &Fq2::zero());
        let zero_inv_t = zero.inv(&mut builder);

        let mut pw = PartialWitness::<F>::new();
        a_add_b_t.set_witness(&mut pw, &a_add_b);
        neg_a_t.set_witness(&mut pw, &neg_a);
        a_sub_b_t.set_witness(&mut pw, &a_sub_b);
        a_mul_b_t.set_witness(&mut pw, &a_mul_b);
        a_mul_constant_t.set_witness(&mut pw, &a_mul_constant);
        a_inv_t.set_witness(&mut pw, &a_inv);
        zero_inv_t.set_witness(&mut pw, &Fq2::zero());
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn fq2_sgn() {
        let rng = &mut rand::thread_rng();
        let a: Fq2 = Fq2::rand(rng);
        let expected_a_sgn = a.sgn();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = Fq2Target::constant(&mut builder, &a);
        let sgn0_a_t = a_t.sgn(&mut builder);
        let expected_sgn0_a_t = builder.constant_bool(expected_a_sgn);
        builder.connect(sgn0_a_t.target, expected_sgn0_a_t.target);
        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn sqrt_with_sgn() {
        let rng = &mut rand::thread_rng();
        let a: Fq2 = {
            // resample a until it is a square
            let mut a = Fq2::rand(rng);
            while !a.legendre().is_qr() {
                a = Fq2::rand(rng);
            }
            a
        };
        assert!(a.legendre().is_qr());
        let sgn: bool = rng.gen();
        let sqrt = a.sqrt().unwrap();
        let expected_sqrt = if sgn == sqrt.sgn() { sqrt } else { -sqrt };
        assert_eq!(expected_sqrt * expected_sqrt, a);
        assert_eq!(expected_sqrt.sgn(), sgn);
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = Fq2Target::constant(&mut builder, &a);
        let sgn_t = builder.constant_bool(sgn);
        let sqrt_t = a_t.sqrt_with_sgn(&mut builder, sgn_t);
        let expected_sqrt_t = Fq2Target::constant(&mut builder, &expected_sqrt);
        sqrt_t.connect(&mut builder, &expected_sqrt_t);
        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
    }
}
