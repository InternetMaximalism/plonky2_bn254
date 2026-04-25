use anyhow::Result;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        challenger::{Challenger, RecursiveChallenger},
        target::Target,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use starky::{
    config::StarkConfig,
    cross_table_lookup::{
        verify_cross_table_lookups, verify_cross_table_lookups_circuit, CrossTableLookup,
        CtlCheckVars, CtlCheckVarsTarget,
    },
    lookup::{get_grand_product_challenge_set, get_grand_product_challenge_set_target},
    proof::{StarkProofWithMetadata, StarkProofWithPublicInputsTarget},
    recursive_verifier::{
        add_virtual_stark_proof_with_pis, verify_stark_proof_with_challenges_circuit,
    },
    stark::Stark,
    verifier::verify_stark_proof_with_challenges,
};

use super::ctl_values::{sum_ctl_values, sum_ctl_values_circuit};

pub(crate) fn verify<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    stark: &S,
    config: &StarkConfig,
    cross_table_lookups: &[CrossTableLookup<F>],
    proof: &StarkProofWithMetadata<F, C, D>,
    public_inputs: &[F],
    extra_looking_values: &HashMap<usize, Vec<Vec<F>>>,
) -> Result<()>
where
{
    let mut challenger = Challenger::<F, C::Hasher>::new();
    challenger.observe_cap(&proof.proof.trace_cap);
    for x in public_inputs.iter() {
        challenger.observe_element(*x);
    }
    let ctl_challenges = get_grand_product_challenge_set(&mut challenger, config.num_challenges);

    let num_lookup_columns = stark.num_lookup_helper_columns(config);
    let (total_num_helpers, _, num_helpers_by_ctl) = CrossTableLookup::num_ctl_helpers_zs_all(
        cross_table_lookups,
        0,
        config.num_challenges,
        stark.constraint_degree(),
    );
    // plonky2 1.x: `CtlCheckVars::from_proofs` (multi-proof) was replaced by
    // `CtlCheckVars::from_proof` (single proof) per-stark, taking the per-CTL
    // helper-column counts directly.
    let ctl_vars = CtlCheckVars::from_proof(
        0,
        &proof.proof,
        cross_table_lookups,
        &ctl_challenges,
        num_lookup_columns,
        total_num_helpers,
        &num_helpers_by_ctl,
    );

    challenger.compact();
    // plonky2 1.x: `StarkProof::get_challenges` now takes (stark,
    // public_inputs, challenger, ctl_challenges, ctl_vars, ignore_trace_cap,
    // config, verifier_circuit_fri_params).
    let stark_challenges = proof.proof.get_challenges(
        stark,
        public_inputs,
        &mut challenger,
        Some(&ctl_challenges),
        Some(&ctl_vars),
        true,
        config,
        None,
    );

    verify_stark_proof_with_challenges(
        stark,
        &proof.proof,
        &stark_challenges,
        Some(&ctl_vars),
        &public_inputs,
        config,
    )?;
    let extra_looking_sums =
        sum_ctl_values(config.num_challenges, &ctl_challenges, extra_looking_values);
    verify_cross_table_lookups::<F, D, 1>(
        cross_table_lookups,
        [proof.proof.openings.ctl_zs_first.clone().unwrap()],
        &extra_looking_sums,
        config,
    )?;

    Ok(())
}

/// Returns the recursive STARK circuit.
pub(crate) fn recursive_verifier<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: &S,
    degree_bits: usize,
    cross_table_lookups: &[CrossTableLookup<F>],
    config: &StarkConfig,
    extra_looking_values: &HashMap<usize, Vec<Vec<Target>>>,
) -> StarkProofWithPublicInputsTarget<D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let num_lookup_columns = stark.num_lookup_helper_columns(config);
    let (total_num_helpers, num_ctl_zs, num_helpers_by_ctl) =
        CrossTableLookup::num_ctl_helpers_zs_all(
            cross_table_lookups,
            0,
            config.num_challenges,
            stark.constraint_degree(),
        );
    let num_ctl_helper_zs = num_ctl_zs + total_num_helpers;
    let stark_proof_with_pi_target = add_virtual_stark_proof_with_pis(
        builder,
        stark,
        config,
        degree_bits,
        num_ctl_helper_zs,
        num_ctl_zs,
    );
    let stark_proof_target = stark_proof_with_pi_target.proof.clone();

    let mut challenger = RecursiveChallenger::<F, C::Hasher, D>::new(builder);
    challenger.observe_cap(&stark_proof_target.trace_cap);
    for x in &stark_proof_with_pi_target.public_inputs {
        challenger.observe_element(*x);
    }
    let ctl_challenges =
        get_grand_product_challenge_set_target(builder, &mut challenger, config.num_challenges);
    let ctl_vars = CtlCheckVarsTarget::from_proof(
        0,
        &stark_proof_target,
        cross_table_lookups,
        &ctl_challenges,
        num_lookup_columns,
        total_num_helpers,
        &num_helpers_by_ctl,
    );
    // plonky2 1.x: `StarkProofTarget::get_challenges` now takes (builder,
    // stark, public_inputs, challenger, ctl_challenges, ctl_vars,
    // degree_bits, ignore_trace_cap, config).
    let challenges = stark_proof_target.get_challenges::<F, C, S>(
        builder,
        stark,
        &stark_proof_with_pi_target.public_inputs,
        &mut challenger,
        Some(&ctl_challenges),
        Some(&ctl_vars),
        degree_bits,
        true,
        config,
    );
    challenger.compact(builder);
    // plonky2 1.x: `verify_stark_proof_with_challenges_circuit` now takes two
    // extra trailing args (`degree_bits`, `min_degree_bits_to_support`).
    verify_stark_proof_with_challenges_circuit::<F, C, _, D>(
        builder,
        stark,
        &stark_proof_target,
        &stark_proof_with_pi_target.public_inputs, // public inputs
        challenges,
        Some(&ctl_vars),
        config,
        degree_bits,
        None,
    );

    let extra_looking_sums = sum_ctl_values_circuit(
        builder,
        config.num_challenges,
        &ctl_challenges,
        extra_looking_values,
    );

    verify_cross_table_lookups_circuit(
        builder,
        cross_table_lookups.to_vec(),
        [stark_proof_target.openings.ctl_zs_first.clone().unwrap()],
        &extra_looking_sums,
        config,
    );
    stark_proof_with_pi_target
}
