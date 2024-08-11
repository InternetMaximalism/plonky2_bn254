use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::generator::SimpleGenerator as _,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::builder_hook::BuilderHookRef,
};

use crate::{
    curves::{g1::G1Target, g2::G2Target},
    fields::{biguint::BigUintTarget, fq::FqTarget},
    generators::{
        fq::{single::FqSingleGenerator, FqExpInputTarget},
        g1::{single::G1SingleGenerator, G1ScalarMulInputTarget},
        g2::{single::G2SingleGenerator, G2ScalarMulInputTarget},
    },
    hook::Bn254Hook,
};

const BN254_HOOK_KEY: &str = "bn254";

pub trait BuilderBn254Stark<F: RichField + Extendable<D>, const D: usize> {
    fn g1_scalar_mul<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        s: BigUintTarget,
        x: G1Target<F, D>,
        offset: G1Target<F, D>,
    ) -> G1Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    fn g2_scalar_mul<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        s: BigUintTarget,
        x: G2Target<F, D>,
        offset: G2Target<F, D>,
    ) -> G2Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    fn fq_exp<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        s: BigUintTarget,
        x: FqTarget<F, D>,
    ) -> FqTarget<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize> BuilderBn254Stark<F, D>
    for CircuitBuilder<F, D>
{
    fn g1_scalar_mul<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        s: BigUintTarget,
        x: G1Target<F, D>,
        offset: G1Target<F, D>,
    ) -> G1Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = G1ScalarMulInputTarget { s, x, offset };
        let output = G1Target::new_unchecked(self);
        let hook = get_bn254_hook_mut::<F, C, D>(self);
        hook.inputs_g1.push(input.clone());
        hook.outputs_g1.push(output.clone());
        let generator = G1SingleGenerator {
            input,
            output: output.clone(),
        };
        self.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
            generator.adapter(),
        )]);
        output
    }

    fn g2_scalar_mul<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        s: BigUintTarget,
        x: G2Target<F, D>,
        offset: G2Target<F, D>,
    ) -> G2Target<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = G2ScalarMulInputTarget { s, x, offset };
        let output = G2Target::new_unchecked(self);
        let hook = get_bn254_hook_mut::<F, C, D>(self);
        hook.inputs_g2.push(input.clone());
        hook.outputs_g2.push(output.clone());
        let generator = G2SingleGenerator {
            input,
            output: output.clone(),
        };
        self.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
            generator.adapter(),
        )]);
        output
    }

    fn fq_exp<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        s: BigUintTarget,
        x: FqTarget<F, D>,
    ) -> FqTarget<F, D>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = FqExpInputTarget { s, x };
        let output = FqTarget::new_unchecked(self);
        let hook = get_bn254_hook_mut::<F, C, D>(self);
        hook.inputs_fq.push(input.clone());
        hook.outputs_fq.push(output.clone());
        let generator = FqSingleGenerator {
            input,
            output: output.clone(),
        };
        self.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
            generator.adapter(),
        )]);
        output
    }
}

fn get_bn254_hook_mut<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> &mut Bn254Hook<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // if the hook is not present, add it
    if builder.get_hook(BN254_HOOK_KEY).is_none() {
        let hook = BuilderHookRef::new(Bn254Hook::<F, C, D>::new());
        builder.add_hook(BN254_HOOK_KEY, hook);
    }
    let hook = builder
        .get_hook_mut(BN254_HOOK_KEY)
        .unwrap()
        .0
        .as_any_mut()
        .downcast_mut::<Bn254Hook<F, C, D>>()
        .unwrap();
    hook
}

#[cfg(test)]
mod tests {
    use crate::{
        builder::BuilderBn254Stark as _,
        curves::{g1::G1Target, g2::G2Target},
        fields::{biguint::CircuitBuilderBiguint, fq::FqTarget},
        starks::common::utils::tests::random_biguint,
    };
    use ark_bn254::{Fq, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::{Field as _, UniformRand as _};
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn builder_bn254_stark() {
        let num_inputs_g1 = 10;
        let num_inputs_g2 = 10;
        let num_inputs_fq = 10;
        let rng = &mut rand::thread_rng();
        let inputs_g1 = (0..num_inputs_g1)
            .map(|_| {
                let s = random_biguint(rng);
                let x = G1Affine::rand(rng);
                let offset = G1Affine::rand(rng);
                (s, x, offset)
            })
            .collect::<Vec<_>>();
        let inputs_g2 = (0..num_inputs_g2)
            .map(|_| {
                let s = random_biguint(rng);
                let x = G2Affine::rand(rng);
                let offset = G2Affine::rand(rng);
                (s, x, offset)
            })
            .collect::<Vec<_>>();
        let inputs_fq = (0..num_inputs_fq)
            .map(|_| {
                let s = random_biguint(rng);
                let x = Fq::rand(rng);
                (s, x)
            })
            .collect::<Vec<_>>();

        let output_g1: Vec<G1Affine> = inputs_g1
            .iter()
            .map(|(s, x, offset)| (x.mul_bigint(s.to_u64_digits()) + offset).into())
            .collect();
        let output_g2: Vec<G2Affine> = inputs_g2
            .iter()
            .map(|(s, x, offset)| (x.mul_bigint(s.to_u64_digits()) + offset).into())
            .collect();
        let output_fq: Vec<Fq> = inputs_fq
            .iter()
            .map(|(s, x)| x.pow(s.to_u64_digits()))
            .collect();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let outputs_g1_t = inputs_g1
            .iter()
            .map(|input| {
                let s = builder.constant_biguint(&input.0);
                let x = G1Target::constant(&mut builder, &input.1);
                let offset = G1Target::constant(&mut builder, &input.2);
                builder.g1_scalar_mul::<C>(s, x, offset)
            })
            .collect::<Vec<_>>();
        let outputs_g2_t = inputs_g2
            .iter()
            .map(|input| {
                let s = builder.constant_biguint(&input.0);
                let x = G2Target::constant(&mut builder, &input.1);
                let offset = G2Target::constant(&mut builder, &input.2);
                builder.g2_scalar_mul::<C>(s, x, offset)
            })
            .collect::<Vec<_>>();
        let outputs_fq_t = inputs_fq
            .iter()
            .map(|input| {
                let s = builder.constant_biguint(&input.0);
                let x = FqTarget::constant(&mut builder, &input.1);
                builder.fq_exp::<C>(s, x)
            })
            .collect::<Vec<_>>();

        let mut pw = PartialWitness::new();
        for (output_g1_t, output_g1) in outputs_g1_t.iter().zip(output_g1.iter()) {
            output_g1_t.set_witness(&mut pw, output_g1);
        }
        for (output_g2_t, output_g2) in outputs_g2_t.iter().zip(output_g2.iter()) {
            output_g2_t.set_witness(&mut pw, output_g2);
        }
        for (output_fq_t, output_fq) in outputs_fq_t.iter().zip(output_fq.iter()) {
            output_fq_t.set_witness(&mut pw, output_fq);
        }
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
