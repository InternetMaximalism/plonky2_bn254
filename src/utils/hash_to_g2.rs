use std::str::FromStr as _;

use ark_bn254::{Fq, Fq2, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;
use num::{BigUint, Zero};
use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::{
        challenger::{Challenger, RecursiveChallenger},
        target::{BoolTarget, Target},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

use crate::{
    builder::BuilderBn254Stark as _,
    curves::g2::G2Target,
    fields::{
        biguint::{BigUintTarget, CircuitBuilderBiguint},
        fq::FqTarget,
        fq2::Fq2Target,
        inv::Inv,
        sgn::Sgn,
    },
    generators::g2::random::set_random_g2,
};
use num::One;

pub trait HashToG2<F: RichField + Extendable<D>, const D: usize> {
    fn cofactor_target(builder: &mut CircuitBuilder<F, D>) -> BigUintTarget;

    fn hash_to_fq2(input: &[F]) -> Fq2;
    fn map_to_g2(input: Fq2) -> G2Affine;
    fn hash_to_g2(input: &[F]) -> G2Affine {
        let u = Self::hash_to_fq2(input);
        Self::map_to_g2(u)
    }

    fn hash_to_fq2_circuit(builder: &mut CircuitBuilder<F, D>, input: &[Target])
        -> Fq2Target<F, D>;

    fn map_to_g2_circuit<C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        input: &Fq2Target<F, D>,
    ) -> G2Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    fn hash_to_g2_circuit<C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        input: &[Target],
    ) -> G2Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let u = Self::hash_to_fq2_circuit(builder, input);
        Self::map_to_g2_circuit::<C>(builder, &u)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> HashToG2<F, D> for G2Target<F, D> {
    fn cofactor_target(builder: &mut CircuitBuilder<F, D>) -> BigUintTarget {
        let cofactor = BigUint::from_str(
            "21888242871839275222246405745257275088844257914179612981679871602714643921549",
        )
        .unwrap();
        builder.constant_biguint(&cofactor)
    }

    fn hash_to_fq2(input: &[F]) -> Fq2 {
        let mut challenger = Challenger::<F, PoseidonHash>::new();
        challenger.observe_elements(input);

        let c0_output = challenger.get_n_challenges(2 * FqTarget::<F, D>::num_modulus_limbs());
        let c0: Fq = f_slice_to_biguint(&c0_output).into();

        let c1_output = challenger.get_n_challenges(2 * FqTarget::<F, D>::num_modulus_limbs());
        let c1: Fq = f_slice_to_biguint(&c1_output).into();

        Fq2::new(c0, c1)
    }

    fn hash_to_fq2_circuit(
        builder: &mut CircuitBuilder<F, D>,
        input: &[Target],
    ) -> Fq2Target<F, D> {
        let mut challenger = RecursiveChallenger::<F, PoseidonHash, D>::new(builder);
        challenger.observe_elements(input);

        let c0_output =
            challenger.get_n_challenges(builder, 2 * FqTarget::<F, D>::num_modulus_limbs());
        let c0_limbs = target_slice_to_biguint_target(builder, &c0_output);
        let c0 = FqTarget::from_value(&c0_limbs, false).take_mod(builder);

        let c1_output =
            challenger.get_n_challenges(builder, 2 * FqTarget::<F, D>::num_modulus_limbs());
        let c1_limbs = target_slice_to_biguint_target(builder, &c1_output);
        let c1 = FqTarget::from_value(&c1_limbs, false).take_mod(builder);

        Fq2Target::from_value(&c0, &c1)
    }

    /// Map a point in Fq2 to a point in G2.
    /// Reference:
    /// 6.6.1. Shallue-van de Woestijne Method
    /// https://datatracker.ietf.org/doc/rfc9380/
    fn map_to_g2(u: Fq2) -> G2Affine {
        let z = Fq2::ONE;
        let gz = Self::g(z);
        let neg_z_by_two = -z / (Fq2::from(2));
        let tv4 = (-gz * Fq2::from(3) * z * z).sqrt().unwrap();
        let tv6 = -Fq2::from(4) * gz / (Fq2::from(3) * z * z);
        let tv1 = u * u * gz;
        let tv2 = Fq2::one() + tv1;
        let tv1 = Fq2::one() - tv1;
        let tv3 = (tv1 * tv2).inv();
        let tv5 = u * tv1 * tv3 * tv4;
        let x1 = neg_z_by_two - tv5;
        let x2 = neg_z_by_two + tv5;
        let x3 = z + tv6 * (tv2 * tv2 * tv3) * (tv2 * tv2 * tv3);
        let gx1 = Self::g(x1);
        let gx2 = Self::g(x2);
        let is_gx1_sq = gx1.legendre().is_qr();
        let is_gx2_sq = gx2.legendre().is_qr();
        let x: Fq2;
        let mut y: Fq2;
        if is_gx1_sq {
            x = x1;
            y = Self::g(x1).sqrt().unwrap();
        } else if is_gx2_sq {
            x = x2;
            y = Self::g(x2).sqrt().unwrap();
        } else {
            x = x3;
            y = Self::g(x3).sqrt().unwrap();
        }
        if u.sgn() != y.sgn() {
            y = -y;
        }
        assert!(Self::g(x) == y * y);
        G2Affine::new_unchecked(x, y).mul_by_cofactor()
    }

    /// Circuit version of `map_to_g2`.
    fn map_to_g2_circuit<C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        u: &Fq2Target<F, D>,
    ) -> G2Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let z = Fq2::ONE;
        let gz = Self::g(z);
        let neg_z_by_two = -z / (Fq2::from(2));
        let tv4 = (-gz * Fq2::from(3) * z * z).sqrt().unwrap();
        let tv6 = -Fq2::from(4) * gz / (Fq2::from(3) * z * z);

        let z = Fq2Target::constant(builder, &z);
        let gz = Fq2Target::constant(builder, &gz);
        let tv4 = Fq2Target::constant(builder, &tv4);
        let tv6 = Fq2Target::constant(builder, &tv6);
        let neg_two_by_z = Fq2Target::constant(builder, &neg_z_by_two);
        let one = Fq2Target::constant(builder, &Fq2::one());

        let tv1 = u.mul(builder, &u).mul(builder, &gz);
        let tv2 = one.add(builder, &tv1);
        let tv1 = one.sub(builder, &tv1);
        let tv3 = tv1.mul(builder, &tv2).inv(builder);
        let tv5 = u.mul(builder, &tv1).mul(builder, &tv3).mul(builder, &tv4);
        let x1 = neg_two_by_z.sub(builder, &tv5);
        let x2 = neg_two_by_z.add(builder, &tv5);
        let tv2tv2tv3 = tv2.mul(builder, &tv2).mul(builder, &tv3);
        let tv2tv2tv3_sq = tv2tv2tv3.mul(builder, &tv2tv2tv3);
        let tv6_tv2tv2tv3_sq = tv6.mul(builder, &tv2tv2tv3_sq);
        let x3 = z.add(builder, &tv6_tv2tv2tv3_sq);
        let gx1 = Self::g_circuit(builder, &x1);
        let gx2 = Self::g_circuit(builder, &x2);
        let is_gx1_sq = gx1.is_square::<C>(builder);
        let is_gx2_sq = gx2.is_square::<C>(builder);

        let x1_or_x2 = x1.select(builder, &x2, &is_gx1_sq);
        let isgx1_or_isgx2 = or_circuit(is_gx1_sq, is_gx2_sq, builder);
        let x = x1_or_x2.select(builder, &x3, &isgx1_or_isgx2);

        let gx = Self::g_circuit(builder, &x);
        let sgn_u = u.sgn(builder);
        let y = gx.sqrt_with_sgn(builder, sgn_u);

        // Guarantee that the `offset`` is not at infinity with `new_checked`.
        let offset = G2Target::new_checked(builder);
        set_random_g2(builder, &offset);
        let cofactor = Self::cofactor_target(builder);
        // The `output_offset` is guaranteed not to be at infinity by the constraints of
        // STARK.
        let output_offset = builder.g2_scalar_mul::<C>(cofactor, G2Target { x, y }, offset.clone());
        // Since it is already guaranteed that the offset is not at infinity,　the
        // `neg_offset`` is also not at infinity.
        let neg_offset = offset.neg(builder);
        // Since both `output_offset` and `neg_offset` are not at infinity, it is safe
        // to call `add`.
        let output = output_offset.add(builder, &neg_offset);
        output
    }
}

fn or_circuit<F, const D: usize>(
    a: BoolTarget,
    b: BoolTarget,
    builder: &mut CircuitBuilder<F, D>,
) -> BoolTarget
where
    F: RichField + Extendable<D>,
{
    // or(a, b) = 1 - (1-a)*(1-b) = a+b-ab
    let a_plus_b = builder.add(a.target, b.target);
    let c = builder.arithmetic(F::NEG_ONE, F::ONE, a.target, b.target, a_plus_b);
    BoolTarget::new_unsafe(c)
}

fn f_slice_to_biguint<F: RichField>(input: &[F]) -> BigUint {
    let limbs = input
        .iter()
        .map(|c| {
            let x = c.to_canonical_u64();
            // discard the high bits because it's not uniformally distributed
            x as u32
        })
        .collect::<Vec<_>>();
    let mut value = BigUint::zero();
    for (i, limb) in limbs.iter().enumerate() {
        value += BigUint::from(*limb) << (i * 32);
    }
    value
}

fn target_slice_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[Target],
) -> BigUintTarget {
    let limbs = input
        .iter()
        .map(|c| {
            let (lo, _hi) = builder.split_low_high(*c, 32, 64);
            // discard the high bits because it's not uniformally distributed
            U32Target(lo)
        })
        .collect::<Vec<_>>();
    BigUintTarget { limbs }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fq2;
    use ark_std::UniformRand;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Sample},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{curves::g2::G2Target, fields::fq2::Fq2Target, utils::hash_to_g2::HashToG2};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn map_to_g2() {
        let rng = &mut rand::thread_rng();
        let input: Fq2 = Fq2::rand(rng);
        let output_expected = G2Target::<F, D>::map_to_g2(input);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_t = Fq2Target::constant(&mut builder, &input);
        let output_t = G2Target::map_to_g2_circuit::<C>(&mut builder, &input_t);

        let mut pw = PartialWitness::new();
        output_t.set_witness(&mut pw, &output_expected);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
    }

    #[test]
    fn hash_to_fq2() {
        let input = (0..8).map(|_| F::rand()).collect::<Vec<_>>();
        let output = G2Target::<F, D>::hash_to_fq2(&input);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_t = input
            .iter()
            .map(|input| builder.constant(*input))
            .collect::<Vec<_>>();
        let output_t = G2Target::hash_to_fq2_circuit(&mut builder, &input_t);

        let mut pw = PartialWitness::new();
        output_t.set_witness(&mut pw, &output);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
    }
}
