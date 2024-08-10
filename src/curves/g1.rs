use ark_bn254::{Fq, G1Affine};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::fields::fq::FqTarget;

/// A target for a G1 element. Infinite points cannot be represented.
#[derive(Clone, Debug)]
pub struct G1Target<F: RichField + Extendable<D>, const D: usize> {
    pub x: FqTarget<F, D>,
    pub y: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> G1Target<F, D> {
    pub fn new_unchecked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = FqTarget::new_unchecked(builder);
        let y = FqTarget::new_unchecked(builder);
        G1Target { x, y }
    }

    pub fn b() -> Fq {
        Fq::from(3)
    }

    pub fn g(x: Fq) -> Fq {
        x * x * x + Self::b()
    }

    pub fn b_target(builder: &mut CircuitBuilder<F, D>) -> FqTarget<F, D> {
        FqTarget::constant(builder, &Self::b())
    }

    pub fn g_circuit(builder: &mut CircuitBuilder<F, D>, x: &FqTarget<F, D>) -> FqTarget<F, D> {
        let x_sq = x.mul(builder, x);
        let x_cubed = x_sq.mul(builder, x);
        let b = Self::b_target(builder);
        let x_cubed_plus_b = x_cubed.add(builder, &b).take_mod(builder);
        x_cubed_plus_b
    }

    /// Create a new G1 target with the x and y coordinates checked to be on the
    /// curve.
    pub fn new_checked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = FqTarget::new_checked(builder);
        let y = FqTarget::new_checked(builder);
        let y_sq = y.mul(builder, &y);
        let g = Self::g_circuit(builder, &x);
        y_sq.connect(builder, &g);
        G1Target { x, y }
    }

    pub fn from_value(x: FqTarget<F, D>, y: FqTarget<F, D>) -> Self {
        G1Target { x, y }
    }

    pub fn is_valid(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let is_x_valid = self.x.is_valid(builder);
        let is_y_valid = self.y.is_valid(builder);
        let is_field_valid = builder.and(is_x_valid, is_y_valid);
        let g = Self::g_circuit(builder, &self.x);
        let y_sq = self.y.mul(builder, &self.y);
        let is_on_equation = y_sq.is_equal(builder, &g);
        builder.and(is_field_valid, is_on_equation)
    }

    /// Determine whether y can be recovered from x.
    pub fn is_recoverable_from_x<C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        x: &FqTarget<F, D>,
    ) -> BoolTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let g = Self::g_circuit(builder, x);
        g.is_square::<C>(builder)
    }

    /// Recover a G1 target from the x coordinate.
    /// y's sgn is assumed to be false (even)
    pub fn recover_from_x(builder: &mut CircuitBuilder<F, D>, x: &FqTarget<F, D>) -> Self {
        let false_t = builder._false();
        let g = Self::g_circuit(builder, x);
        let y = g.sqrt_with_sgn(builder, false_t);
        G1Target { x: x.clone(), y }
    }

    pub fn constant(builder: &mut CircuitBuilder<F, D>, value: &G1Affine) -> Self {
        let x_target = FqTarget::constant(builder, &value.x);
        let y_target = FqTarget::constant(builder, &value.y);
        G1Target {
            x: x_target,
            y: y_target,
        }
    }

    pub fn connect(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) {
        self.x.connect(builder, &other.x);
        self.y.connect(builder, &other.y);
    }

    pub fn neg(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = self.x.clone();
        let y = self.y.neg(builder).take_mod(builder);
        G1Target { x, y }
    }

    /// Add `self` and `other`.
    /// The caller must ensure that `self` and `other` are points on the
    /// elliptic curve. The return value is never the point at infinity.
    /// other != - self is constrained in this function.
    pub fn add(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        let delta_x = other.x.sub(builder, &self.x);
        let inv_delta_x = delta_x.inv(builder);
        let is_eq = delta_x.is_zero(builder);

        // lambda_neq = (y2 - y1) / (x2 - x1)
        let delta_y = other.y.sub(builder, &self.y);
        let lambda_neq = delta_y.mul(builder, &inv_delta_x);

        // lambda_eq = (3 * x1^2) / (2 * y1)
        let two_y = self.y.mul_constant_u32(builder, 2);
        let inv_two_y = two_y.inv(builder);
        let x_sq = self.x.mul(builder, &self.x);
        let three_x_sq = x_sq.mul_constant_u32(builder, 3);
        let lambda_eq = three_x_sq.mul(builder, &inv_two_y);
        // assert self.y == other.y if self.x == other.x
        self.y.connect_conditional(builder, &other.y, &is_eq);

        // lambda = lambda_eq if x1 == x2 else lambda_neq
        let lambda = lambda_eq.select(builder, &lambda_neq, &is_eq);

        let lambda_sq = lambda.mul(builder, &lambda);
        let x_sum = self.x.add(builder, &other.x);
        let x = lambda_sq.sub(builder, &x_sum).take_mod(builder);
        let x_diff = self.x.sub(builder, &x);
        let lambda_x_diff = lambda.mul(builder, &x_diff);
        let y = lambda_x_diff.sub(builder, &self.y).take_mod(builder);
        Self { x, y }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> G1Target<F, D> {
    pub fn to_vec(&self) -> Vec<Target> {
        self.x.to_vec().into_iter().chain(self.y.to_vec()).collect()
    }

    pub fn from_slice(input: &[Target]) -> Self {
        let num_limbs = FqTarget::<F, D>::num_modulus_limbs();
        assert_eq!(input.len(), 2 * num_limbs);
        let x = FqTarget::from_slice(&input[0..num_limbs]);
        let y = FqTarget::from_slice(&input[num_limbs..]);
        G1Target { x, y }
    }

    pub fn set_witness<W: WitnessWrite<F>>(&self, witness: &mut W, value: &G1Affine) {
        self.x.set_witness(witness, &value.x);
        self.y.set_witness(witness, &value.y);
    }

    pub fn get_witness<W: Witness<F>>(&self, witness: &W) -> G1Affine {
        let x = self.x.get_witness(witness);
        let y = self.y.get_witness(witness);
        G1Affine::new_unchecked(x, y)
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{fq::FqTarget, recover::RecoverFromX};
    use ark_bn254::{Fq, G1Affine};
    use ark_std::UniformRand;
    use num::One;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::G1Target;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn g1_add_circuit() {
        let rng = &mut rand::thread_rng();
        let a = G1Affine::rand(rng);
        let b = G1Affine::rand(rng);
        let c: G1Affine = (a + b + b).into();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = G1Target::new_checked(&mut builder);
        let b_t = G1Target::new_checked(&mut builder);
        let double_b_t = b_t.add(&mut builder, &b_t);
        let c_t = a_t.add(&mut builder, &double_b_t);

        let mut pw = PartialWitness::new();
        a_t.set_witness(&mut pw, &a);
        b_t.set_witness(&mut pw, &b);
        c_t.set_witness(&mut pw.clone(), &c);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn g1_recover_from_x() {
        let rng = &mut rand::thread_rng();
        let inputs = (0..1 << 7).map(|_| Fq::rand(rng)).collect::<Vec<_>>();
        let is_recoverable_keys = inputs
            .iter()
            .map(|x| G1Affine::is_recoverable_from_x(*x))
            .collect::<Vec<_>>();
        let outputs = inputs
            .iter()
            .map(|x| {
                if G1Affine::is_recoverable_from_x(*x) {
                    Some(G1Affine::recover_from_x(*x))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let inputs_t = inputs
            .iter()
            .map(|input| FqTarget::constant(&mut builder, input))
            .collect::<Vec<_>>();
        let is_recoverable_keys_t = inputs_t
            .iter()
            .map(|input| G1Target::is_recoverable_from_x::<C>(&mut builder, input))
            .collect::<Vec<_>>();
        let outputs_t = inputs_t
            .iter()
            .zip(is_recoverable_keys.iter())
            .map(|(input, is_recoverable)| {
                if *is_recoverable {
                    Some(G1Target::recover_from_x(&mut builder, input))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut pw = PartialWitness::new();
        for (t, w) in is_recoverable_keys_t.iter().zip(is_recoverable_keys) {
            pw.set_bool_target(*t, w);
        }
        for (t, w) in outputs_t.iter().zip(outputs) {
            if t.is_some() {
                assert!(w.is_some());
                t.clone().unwrap().set_witness(&mut pw, &w.unwrap());
            }
        }
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn g1_is_valid() {
        let rng = &mut rand::thread_rng();
        let a: G1Affine = G1Affine::rand(rng);
        let b = G1Affine::new_unchecked(a.x, a.y + Fq::one());

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = G1Target::new_unchecked(&mut builder);
        let b_t = G1Target::new_unchecked(&mut builder);

        let is_valid_a = a_t.is_valid(&mut builder);
        let is_valid_b = b_t.is_valid(&mut builder);

        let mut pw = PartialWitness::<F>::new();
        a_t.set_witness(&mut pw, &a);
        b_t.set_witness(&mut pw, &b);
        pw.set_bool_target(is_valid_a, true);
        pw.set_bool_target(is_valid_b, false);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
