use crate::{
    curves::g2::G2Target,
    generators::to_u16::ToU16,
    starks::{
        common::{ctl_values::set_ctl_values_target, verifier::recursive_verifier},
        curves::g2::{
            scalar_mul_ctl::{g2_generate_ctl_values, g2_scalar_mul_ctl},
            scalar_mul_stark::G2ScalarMulStark,
            scalar_mul_view::G2_PERIOD,
        },
        LIMB_BITS,
    },
};
use ark_bn254::G2Affine;
use ark_ec::AffineRepr;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::PartitionWitness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::timing::TimingTree,
};
use starky::{
    config::StarkConfig, proof::StarkProofTarget, recursive_verifier::set_stark_proof_target,
};

use super::G2ScalarMulInputTarget;

#[derive(Clone, Debug)]
pub struct G2StarkProofGenerator<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub(crate) inputs: Vec<G2ScalarMulInputTarget<F, D>>,
    pub(crate) outputs: Vec<G2Target<F, D>>,
    pub(crate) extra_looking_values: HashMap<usize, Vec<Vec<Target>>>,
    pub(crate) stark_proof: StarkProofTarget<D>,
    pub(crate) zero: Target, // used for set_stark_proof_target
    _config: std::marker::PhantomData<C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    G2StarkProofGenerator<F, C, D>
{
    pub fn new(builder: &mut CircuitBuilder<F, D>, inputs: &[G2ScalarMulInputTarget<F, D>]) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut extra_looking_values = HashMap::new();
        let inputs_with_timestamp = inputs
            .iter()
            .enumerate()
            .map(|(timestamp, input)| {
                let mut input = input.to_u16(builder);
                input.push(builder.constant(F::from_canonical_usize(timestamp)));
                input
            })
            .collect::<Vec<_>>();
        let outputs = (0..inputs.len())
            .map(|_| G2Target::new_unchecked(builder))
            .collect::<Vec<_>>();
        let outputs_with_timestamp = outputs
            .iter()
            .enumerate()
            .map(|(timestamp, output)| {
                let mut output = output.to_u16(builder);
                output.push(builder.constant(F::from_canonical_usize(timestamp)));
                output
            })
            .collect::<Vec<_>>();
        extra_looking_values.insert(0, inputs_with_timestamp);
        extra_looking_values.insert(1, outputs_with_timestamp);

        let stark = G2ScalarMulStark::new();
        let config = StarkConfig::standard_fast_config();
        let degree_bits = (1 << LIMB_BITS)
            .max(G2_PERIOD * inputs.len())
            .next_power_of_two()
            .trailing_zeros() as usize;
        let cross_table_lookups = g2_scalar_mul_ctl();
        let proof_t = recursive_verifier::<F, C, _, D>(
            builder,
            &stark,
            degree_bits,
            &cross_table_lookups,
            &config,
            &extra_looking_values,
        );
        let zero = builder.zero();

        Self {
            inputs: inputs.to_vec(),
            outputs,
            stark_proof: proof_t.proof,
            extra_looking_values,
            zero,
            _config: std::marker::PhantomData,
        }
    }
}

impl<F, C, const D: usize> SimpleGenerator<F, D> for G2StarkProofGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn id(&self) -> String {
        "G2StarkProofGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.inputs
            .iter()
            .flat_map(|input| {
                input
                    .x
                    .to_vec()
                    .into_iter()
                    .chain(input.offset.to_vec())
                    .chain(input.s.limbs.iter().map(|limb| limb.0).collect::<Vec<_>>())
            })
            .collect()
    }

    fn run_once(&self, pw: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let inputs = self
            .inputs
            .iter()
            .enumerate()
            .map(|(timestamp, input)| (input.get_witness(pw), timestamp))
            .collect::<Vec<_>>();
        let outputs: Vec<G2Affine> = inputs
            .iter()
            .map(|(input, _)| (input.x.mul_bigint(input.s.to_u64_digits()) + input.offset).into())
            .collect::<Vec<_>>();
        for (output_t, output) in self.outputs.iter().zip(outputs.iter()) {
            output_t.set_witness(out_buffer, output);
        }
        let extra_looking_values = g2_generate_ctl_values::<F>(&inputs);
        let stark = G2ScalarMulStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let cross_table_lookups = g2_scalar_mul_ctl::<F>();
        let trace = stark.generate_trace(&inputs, 1 << LIMB_BITS);
        let stark_proof = crate::starks::common::prover::prove::<F, C, _, D>(
            &stark,
            &config,
            &trace,
            &cross_table_lookups,
            &[],
            &mut TimingTree::default(),
        )
        .unwrap();
        crate::starks::common::verifier::verify(
            &stark,
            &config,
            &cross_table_lookups,
            &stark_proof,
            &[],
            &extra_looking_values,
        )
        .unwrap();
        set_stark_proof_target(out_buffer, &self.stark_proof, &stark_proof.proof, self.zero);
        set_ctl_values_target(
            out_buffer,
            &self.extra_looking_values,
            &extra_looking_values,
        );
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        unimplemented!()
    }

    fn deserialize(
        _src: &mut plonky2::util::serialization::Buffer,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        fields::biguint::CircuitBuilderBiguint,
        generators::g2::single::G2SingleGenerator,
        starks::{
            common::utils::tests::random_biguint, curves::g2::scalar_mul_stark::G2ScalarMulInput,
        },
    };

    use super::*;
    use ark_ff::UniformRand;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    #[test]
    fn g2_stark_proof_generator() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut rng = rand::thread_rng();
        let inputs = (0..128)
            .map(|_| {
                let x = G2Affine::rand(&mut rng);
                let s = random_biguint(&mut rng);
                let offset = G2Affine::rand(&mut rng);
                G2ScalarMulInput { x, s, offset }
            })
            .collect::<Vec<_>>();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let inputs_t = inputs
            .iter()
            .map(|input| {
                let x = G2Target::constant(&mut builder, &input.x);
                let s = builder.constant_biguint(&input.s);
                let offset = G2Target::constant(&mut builder, &input.offset);
                G2ScalarMulInputTarget { x, s, offset }
            })
            .collect::<Vec<_>>();
        let outputs_t = inputs_t
            .iter()
            .map(|input_t| {
                let output_t = G2Target::new_unchecked(&mut builder);
                let generator = G2SingleGenerator {
                    input: input_t.clone(),
                    output: output_t.clone(),
                };
                builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
                    generator.adapter(),
                )]);
                output_t
            })
            .collect::<Vec<_>>();
        let generator = G2StarkProofGenerator::<F, C, D>::new(&mut builder, &inputs_t);
        builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
            generator.clone().adapter(),
        )]);
        for (a, b) in generator.outputs.iter().zip(outputs_t) {
            a.connect(&mut builder, &b);
        }
        let pw = PartialWitness::new();
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
