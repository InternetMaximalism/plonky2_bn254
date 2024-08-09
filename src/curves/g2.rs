use ark_bn254::{Fq2, G2Affine};
use ark_ff::MontFp;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::fields::{fq::FqTarget, fq2::Fq2Target};

/// A target for a G2 element. Infinite points cannot be represented.
#[derive(Clone, Debug)]
pub struct G2Target<F: RichField + Extendable<D>, const D: usize> {
    pub x: Fq2Target<F, D>,
    pub y: Fq2Target<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> G2Target<F, D> {
    pub fn new_unchecked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = Fq2Target::new_unchecked(builder);
        let y = Fq2Target::new_unchecked(builder);
        G2Target { x, y }
    }

    pub fn b() -> Fq2 {
        Fq2::new(
            MontFp!(
                "19485874751759354771024239261021720505790618469301721065564631296452457478373"
            ),
            MontFp!("266929791119991161246907387137283842545076965332900288569378510910307636690"),
        )
    }

    pub fn b_target(builder: &mut CircuitBuilder<F, D>) -> Fq2Target<F, D> {
        Fq2Target::constant(builder, &Self::b())
    }

    pub fn g(x: Fq2) -> Fq2 {
        x * x * x + Self::b()
    }

    pub fn g_circuit(builder: &mut CircuitBuilder<F, D>, x: &Fq2Target<F, D>) -> Fq2Target<F, D> {
        let x_sq = x.mul(builder, x);
        let x_cubed = x_sq.mul(builder, x);
        let b = Self::b_target(builder);
        let x_cubed_plus_b = x_cubed.add(builder, &b).take_mod(builder);
        x_cubed_plus_b
    }

    /// Create a new G2 target with the x and y coordinates checked to be on the
    /// curve.
    pub fn new_checked(builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = Fq2Target::new_checked(builder);
        let y = Fq2Target::new_checked(builder);
        let y_sq = y.mul(builder, &y);
        let g = Self::g_circuit(builder, &x);
        y_sq.connect(builder, &g);
        G2Target { x, y }
    }

    pub fn from_value(x: Fq2Target<F, D>, y: Fq2Target<F, D>) -> Self {
        G2Target { x, y }
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

    pub fn constant(builder: &mut CircuitBuilder<F, D>, value: &G2Affine) -> Self {
        let x_target = Fq2Target::constant(builder, &value.x);
        let y_target = Fq2Target::constant(builder, &value.y);
        G2Target {
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
        G2Target { x, y }
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

impl<F: RichField + Extendable<D>, const D: usize> G2Target<F, D> {
    pub fn to_vec(&self) -> Vec<Target> {
        self.x.to_vec().into_iter().chain(self.y.to_vec()).collect()
    }

    pub fn from_slice(input: &[Target]) -> Self {
        let num_limbs = FqTarget::<F, D>::num_modulus_limbs();
        assert_eq!(input.len(), 4 * num_limbs);
        let x = Fq2Target::from_slice(&input[0..2 * num_limbs]);
        let y = Fq2Target::from_slice(&input[2 * num_limbs..]);
        G2Target { x, y }
    }

    pub fn set_witness<W: WitnessWrite<F>>(&self, witness: &mut W, value: &G2Affine) {
        self.x.set_witness(witness, &value.x);
        self.y.set_witness(witness, &value.y);
    }

    pub fn get_witness<W: Witness<F>>(&self, witness: &W) -> G2Affine {
        let x = self.x.get_witness(witness);
        let y = self.y.get_witness(witness);
        G2Affine::new_unchecked(x, y)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G2Affine;
    use ark_std::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::G2Target;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn g2_add_circuit() {
        let rng = &mut rand::thread_rng();
        let a = G2Affine::rand(rng);
        let b = G2Affine::rand(rng);
        let c: G2Affine = (a + b + b).into();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = G2Target::new_checked(&mut builder);
        let b_t = G2Target::new_checked(&mut builder);
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
}
