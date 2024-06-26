use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    builder::BuilderBn254Stark as _, curves::g1::G1Target, fields::biguint::BigUintTarget,
    generators::g1::random::set_random_g1,
};

/// This function performs the calculation of multi scalar multiplication.
/// The caller must ensure the following:
/// - Each limb of BigUintTarget is range checked
//  - Each limb of G1Target is range checked and is a point on the elliptic curve
///   (not the point at infinity).
/// If the result of the MSM is the point at infinity, the proof cannot be
/// generated.
pub fn g1_msm<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[(BigUintTarget, G1Target<F, D>)],
) -> G1Target<F, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut offset = G1Target::new_checked(builder);
    set_random_g1(builder, &offset);
    let neg_offset = offset.neg(builder);
    for (s, x) in inputs {
        offset = builder.g1_scalar_mul::<C>(s.clone(), x.clone(), offset);
    }
    offset.add(builder, &neg_offset)
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        curves::g1::G1Target, fields::biguint::CircuitBuilderBiguint as _,
        starks::common::utils::tests::random_biguint, utils::g1_msm::g1_msm,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn g1_msm_test() {
        let num_inputs = 128;
        let rng = &mut rand::thread_rng();
        let inputs = (0..num_inputs)
            .map(|_| {
                let s = random_biguint(rng);
                let x = G1Affine::rand(rng);
                (s, x)
            })
            .collect::<Vec<_>>();
        let output: G1Affine = inputs.iter().fold(G1Affine::zero(), |acc, (s, x)| {
            (acc + x.mul_bigint(s.to_u64_digits())).into()
        });

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let inputs_t = inputs
            .iter()
            .map(|(s, x)| {
                let s_t = builder.constant_biguint(s);
                let x_t = G1Target::constant(&mut builder, x);
                (s_t, x_t)
            })
            .collect::<Vec<_>>();
        let output_t = g1_msm::<F, C, D>(&mut builder, &inputs_t);

        let mut pw = PartialWitness::<F>::new();
        output_t.set_witness(&mut pw, &output);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
