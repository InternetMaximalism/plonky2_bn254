use crate::{
    fields::fq::FqTarget,
    generators::to_u16::ToU16,
    starks::{
        common::{ctl_values::set_ctl_values_target, verifier::recursive_verifier},
        fields::{
            exp_ctl::{fq_exp_ctl, fq_generate_ctl_values},
            exp_stark::FqExpStark,
            exp_view::FQ_PERIOD,
        },
        LIMB_BITS,
    },
};
use ark_bn254::Fq;
use ark_ff::Field as _;
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

use super::FqExpInputTarget;

#[derive(Clone, Debug)]
pub struct FqStarkProofGenerator<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub(crate) inputs: Vec<FqExpInputTarget<F, D>>,
    pub(crate) outputs: Vec<FqTarget<F, D>>,
    pub(crate) extra_looking_values: HashMap<usize, Vec<Vec<Target>>>,
    pub(crate) stark_proof: StarkProofTarget<D>,
    pub(crate) zero: Target, // used for set_stark_proof_target
    _config: std::marker::PhantomData<C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    FqStarkProofGenerator<F, C, D>
{
    pub fn new(builder: &mut CircuitBuilder<F, D>, inputs: &[FqExpInputTarget<F, D>]) -> Self
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
            .map(|_| FqTarget::new_unchecked(builder))
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

        let stark = FqExpStark::new();
        let config = StarkConfig::standard_fast_config();
        let degree_bits = (1 << LIMB_BITS)
            .max(FQ_PERIOD * inputs.len())
            .next_power_of_two()
            .trailing_zeros() as usize;
        let cross_table_lookups = fq_exp_ctl();
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

impl<F, C, const D: usize> SimpleGenerator<F, D> for FqStarkProofGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn id(&self) -> String {
        "FqStarkProofGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.inputs
            .iter()
            .flat_map(|input| {
                input
                    .x
                    .to_vec()
                    .into_iter()
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
        let outputs: Vec<Fq> = inputs
            .iter()
            .map(|(input, _)| input.x.pow(input.s.to_u64_digits()))
            .collect::<Vec<_>>();
        for (output_t, output) in self.outputs.iter().zip(outputs.iter()) {
            output_t.set_witness(out_buffer, output);
        }
        let extra_looking_values = fq_generate_ctl_values::<F>(&inputs);
        let stark = FqExpStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let cross_table_lookups = fq_exp_ctl::<F>();
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
        generators::fq::single::FqSingleGenerator,
        starks::{common::utils::tests::random_biguint, fields::exp_stark::FqExpInput},
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
    fn fq_stark_proof_generator() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut rng = rand::thread_rng();
        let inputs = (0..128)
            .map(|_| {
                let x = Fq::rand(&mut rng);
                let s = random_biguint(&mut rng);
                FqExpInput { x, s }
            })
            .collect::<Vec<_>>();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let inputs_t = inputs
            .iter()
            .map(|input| {
                let x = FqTarget::constant(&mut builder, &input.x);
                let s = builder.constant_biguint(&input.s);
                FqExpInputTarget { x, s }
            })
            .collect::<Vec<_>>();
        let outputs_t = inputs_t
            .iter()
            .map(|input_t| {
                let output_t = FqTarget::new_unchecked(&mut builder);
                let generator = FqSingleGenerator {
                    input: input_t.clone(),
                    output: output_t.clone(),
                };
                builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
                    generator.adapter(),
                )]);
                output_t
            })
            .collect::<Vec<_>>();
        let generator = FqStarkProofGenerator::<F, C, D>::new(&mut builder, &inputs_t);
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
