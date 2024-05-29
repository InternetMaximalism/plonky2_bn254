use std::fmt::Debug;

use itertools::Itertools;
use num::{Signed, Zero as _};
use num_bigint::{BigInt, Sign};
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field, types::PrimeField64},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{
    modular::{
        pol_utils::pol_remove_root_2exp,
        utils::{bigint_to_columns, columns_to_bigint},
    },
    LIMB_BITS, N_LIMBS, U256,
};

use super::pol_utils::{
    pol_add_assign, pol_add_assign_ext_circuit, pol_adjoin_root, pol_adjoin_root_ext_circuit,
    pol_mul_wide2, pol_mul_wide2_ext_circuit, pol_sub_assign, pol_sub_assign_ext_circuit,
};

const AUX_COEFF_ABS_MAX: i64 = 1 << 29;

pub(crate) const MODULUS_AUX_ZERO_LEN: usize = 5 * N_LIMBS;

/// Auxiliary information to ensure that the given number is divisible by the modulus
/// Each field except `quot_abs` is subject to range checks of 0 <= x < 2^16
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ModulusZeroAux<F> {
    pub(crate) is_quot_positive: F,
    pub(crate) quot_abs: [F; N_LIMBS + 1],
    pub(crate) aux_input_lo: [F; 2 * N_LIMBS - 1],
    pub(crate) aux_input_hi: [F; 2 * N_LIMBS - 1],
}

/// Generate auxiliary information to ensure that the given `input`
/// is divisible by the modulus
pub(crate) fn generate_modulus_zero<F: PrimeField64>(
    modulus: &BigInt,
    input: &[i64; 2 * N_LIMBS - 1],
) -> ModulusZeroAux<F> {
    let input_bg = columns_to_bigint(&input);
    debug_assert!(&input_bg % modulus == BigInt::zero());
    let modulus_limbs = bigint_to_columns(modulus);
    let quot = &input_bg / modulus;
    let is_quot_positive = match quot.sign() {
        Sign::Minus => F::ZERO,
        Sign::NoSign => F::ZERO,
        Sign::Plus => F::ONE,
    };
    let quot_limbs = bigint_to_columns::<{ N_LIMBS + 1 }>(&quot);
    let quot_abs_limbs = bigint_to_columns::<{ N_LIMBS + 1 }>(&quot.abs());
    // constr_poly = zero_pol  - s(x)*m(x).
    let mut constr_poly = [0i64; 2 * N_LIMBS];
    constr_poly[..2 * N_LIMBS - 1].copy_from_slice(input);
    let prod: [i64; 2 * N_LIMBS] = pol_mul_wide2(quot_limbs, modulus_limbs);
    pol_sub_assign(&mut constr_poly, &prod);
    // aux_limbs = constr/(x- β)
    let mut aux_limbs = pol_remove_root_2exp::<LIMB_BITS, _, { 2 * N_LIMBS }>(constr_poly);
    debug_assert!(aux_limbs[31] == 0);
    for c in aux_limbs.iter_mut() {
        *c += AUX_COEFF_ABS_MAX;
    }
    debug_assert!(aux_limbs.iter().all(|&c| c.abs() <= 2 * AUX_COEFF_ABS_MAX));
    let aux_input_lo = aux_limbs[..2 * N_LIMBS - 1]
        .iter()
        .map(|&c| F::from_canonical_u16(c as u16))
        .collect_vec();
    let aux_input_hi = aux_limbs[..2 * N_LIMBS - 1]
        .iter()
        .map(|&c| F::from_canonical_u16((c >> LIMB_BITS) as u16))
        .collect_vec();
    let quot_abs = quot_abs_limbs.map(|x| F::from_canonical_i64(x));
    ModulusZeroAux {
        is_quot_positive,
        quot_abs,
        aux_input_lo: aux_input_lo.try_into().unwrap(),
        aux_input_hi: aux_input_hi.try_into().unwrap(),
    }
}

/// Evaluate the constraint that the given `input` is divisible by the modulus
pub(crate) fn eval_modulus_zero<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    modulus: U256<P>,
    input: [P; 2 * N_LIMBS - 1],
    aux: ModulusZeroAux<P>,
) {
    yield_constr
        .constraint(filter * (aux.is_quot_positive * aux.is_quot_positive - aux.is_quot_positive));
    let quot_sign = P::Scalar::TWO * aux.is_quot_positive - P::ONES;
    let quot = aux
        .quot_abs
        .iter()
        .map(|&limb| quot_sign * limb)
        .collect_vec();
    // constr_poly = q(x) * m(x)
    let mut constr_poly: [_; 2 * N_LIMBS] = pol_mul_wide2(quot.try_into().unwrap(), modulus.value);
    let base = P::Scalar::from_canonical_u64(1 << LIMB_BITS);
    let offset = P::Scalar::from_canonical_u64(AUX_COEFF_ABS_MAX as u64);

    // constr_poly = q(x) * m(x) + (x - β) * s(x)
    let mut aux_poly = [P::ZEROS; 2 * N_LIMBS];
    aux_poly[..2 * N_LIMBS - 1]
        .iter_mut()
        .enumerate()
        .for_each(|(i, c)| {
            *c = aux.aux_input_lo[i] - offset;
            *c += base * aux.aux_input_hi[i];
        });
    pol_add_assign(&mut constr_poly, &pol_adjoin_root(aux_poly, base));

    pol_sub_assign(&mut constr_poly, &input);
    for &c in constr_poly.iter() {
        yield_constr.constraint(filter * c);
    }
}

pub(crate) fn eval_modulus_zero_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    modulus: U256<ExtensionTarget<D>>,
    input: [ExtensionTarget<D>; 2 * N_LIMBS - 1],
    aux: ModulusZeroAux<ExtensionTarget<D>>,
) {
    // validate quot_sign
    // t = is_quot_positive^2 - is_quot_positive
    let t = builder.mul_sub_extension(
        aux.is_quot_positive,
        aux.is_quot_positive,
        aux.is_quot_positive,
    );
    let t_filtered = builder.mul_extension(filter, t);
    yield_constr.constraint(builder, t_filtered);

    let one = builder.constant_extension(F::Extension::ONE);
    let two = builder.constant_extension(F::Extension::TWO);
    let quot_sign = builder.mul_sub_extension(two, aux.is_quot_positive, one);
    let quot = aux
        .quot_abs
        .iter()
        .map(|&limb| builder.mul_extension(quot_sign, limb))
        .collect_vec();

    // constr_poly = q(x) * m(x)
    let mut constr_poly: [_; 2 * N_LIMBS] =
        pol_mul_wide2_ext_circuit(builder, quot.try_into().unwrap(), modulus.value);
    // constr_poly = q(x) * m(x) + (x - β) * s(x)
    let offset =
        builder.constant_extension(F::Extension::from_canonical_u64(AUX_COEFF_ABS_MAX as u64));
    let zero = builder.zero_extension();
    let mut aux_poly = [zero; 2 * N_LIMBS];
    let base = F::from_canonical_u64(1u64 << LIMB_BITS);
    aux_poly[..2 * N_LIMBS - 1]
        .iter_mut()
        .enumerate()
        .for_each(|(i, c)| {
            *c = builder.sub_extension(aux.aux_input_lo[i], offset);
            *c = builder.mul_const_add_extension(base, aux.aux_input_hi[i], *c);
        });
    let base = builder.constant_extension(base.into());
    let t = pol_adjoin_root_ext_circuit(builder, aux_poly, base);
    pol_add_assign_ext_circuit(builder, &mut constr_poly, &t);

    // q(x) * m(x) + (x - β) * s(x) - zero_pol = 0
    pol_sub_assign_ext_circuit(builder, &mut constr_poly, &input);
    for &c in constr_poly.iter() {
        let t = builder.mul_extension(filter, c);
        yield_constr.constraint(builder, t);
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use crate::starks::{
        modular::pol_utils::{
            pol_mul_wide, pol_mul_wide_ext_circuit, pol_sub_normal, pol_sub_normal_ext_circuit,
        },
        utils::{
            bn254_base_modulus_bigint, bn254_base_modulus_extension_target,
            bn254_base_modulus_packfield,
        },
    };
    use ark_bn254::Fq;
    use ark_ff::UniformRand;
    use plonky2::{
        field::{
            extension::Extendable, goldilocks_field::GoldilocksField, polynomial::PolynomialValues,
        },
        hash::hash_types::RichField,
        iop::{ext_target::ExtensionTarget, witness::PartialWitness},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
        util::timing::TimingTree,
    };
    use starky::{
        config::StarkConfig,
        evaluation_frame::{StarkEvaluationFrame as _, StarkFrame},
        recursive_verifier::{
            add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target,
            verify_stark_proof_circuit,
        },
        stark::Stark,
        util::trace_rows_to_poly_values,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn modulus_zero() {
        let mut rng = rand::thread_rng();
        let input = (0..10)
            .map(|_| {
                let a = Fq::rand(&mut rng);
                let b = Fq::rand(&mut rng);
                (a, b)
            })
            .collect::<Vec<_>>();
        let stark = ModZeroStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let trace = stark.generate_trace(&input, 8);
        let mut timing = TimingTree::default();
        let proof =
            starky::prover::prove::<F, C, _, D>(stark, &config, trace, &[], &mut timing).unwrap();
        starky::verifier::verify_stark_proof(stark, proof.clone(), &config).unwrap();

        let circuit_config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let degree_bits = proof.proof.recover_degree_bits(&config);
        let proof_t =
            add_virtual_stark_proof_with_pis(&mut builder, &stark, &config, degree_bits, 0, 0);
        verify_stark_proof_circuit::<F, C, _, D>(&mut builder, stark, proof_t.clone(), &config);
        let zero = builder.zero();
        let mut pw = PartialWitness::new();
        set_stark_proof_with_pis_target(&mut pw, &proof_t, &proof, zero);
        let circuit = builder.build::<C>();
        let circuit_proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(circuit_proof).is_ok());
    }

    const G1_ADD_VIEW_LEN: usize = 3 * N_LIMBS + MODULUS_AUX_ZERO_LEN + 1;
    #[repr(C)]
    #[derive(Clone, Default)]
    struct ModZeroView<F: Copy + Clone + Default> {
        a: U256<F>,
        b: U256<F>,
        c: U256<F>,
        aux: ModulusZeroAux<F>,
        filter: F,
    }

    impl<T: Copy + Clone + Default> ModZeroView<T> {
        fn to_slice(&self) -> &[T] {
            unsafe { std::slice::from_raw_parts(self as *const Self as *const T, G1_ADD_VIEW_LEN) }
        }
        fn from_slice(slice: &[T]) -> &Self {
            assert_eq!(slice.len(), G1_ADD_VIEW_LEN);
            unsafe { &*(slice.as_ptr() as *const Self) }
        }
    }

    #[derive(Clone, Copy)]
    struct ModZeroStark<F: RichField + Extendable<D>, const D: usize> {
        _phantom: PhantomData<F>,
    }

    impl<F: RichField + Extendable<D>, const D: usize> ModZeroStark<F, D> {
        fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }

        fn generate_trace(&self, input: &[(Fq, Fq)], min_rows: usize) -> Vec<PolynomialValues<F>> {
            let num_rows = min_rows.max(input.len()).next_power_of_two();
            let mut rows = Vec::<[F; G1_ADD_VIEW_LEN]>::with_capacity(num_rows);
            for (a, b) in input {
                let c = a * b;
                let a_i64 = U256::<F>::from(*a).to_i64();
                let b_i64 = U256::<F>::from(*b).to_i64();
                let c_i64 = U256::<F>::from(c).to_i64();

                let a_mul_b = pol_mul_wide(a_i64.value, b_i64.value);
                let mut c_full = [0; 2 * N_LIMBS - 1];
                c_full[0..N_LIMBS].copy_from_slice(&c_i64.value);
                let diff = pol_sub_normal(a_mul_b, c_full);
                let aux = generate_modulus_zero::<F>(&bn254_base_modulus_bigint(), &diff);
                let view = ModZeroView {
                    a: U256::<F>::from(*a),
                    b: U256::<F>::from(*b),
                    c: U256::<F>::from(c),
                    aux,
                    filter: F::ONE,
                };
                rows.push(view.to_slice().to_vec().try_into().unwrap());
            }
            let default_row: [F; G1_ADD_VIEW_LEN] = ModZeroView::default()
                .to_slice()
                .to_vec()
                .try_into()
                .unwrap();
            rows.resize(num_rows, default_row);
            trace_rows_to_poly_values(rows)
        }
    }

    impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ModZeroStark<F, D> {
        type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, G1_ADD_VIEW_LEN, 0>
        where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>;

        type EvaluationFrameTarget =
            StarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, G1_ADD_VIEW_LEN, 0>;

        fn eval_packed_generic<FE, P, const D2: usize>(
            &self,
            vars: &Self::EvaluationFrame<FE, P, D2>,
            yield_constr: &mut starky::constraint_consumer::ConstraintConsumer<P>,
        ) where
            FE: plonky2::field::extension::FieldExtension<D2, BaseField = F>,
            P: plonky2::field::packed::PackedField<Scalar = FE>,
        {
            let view = ModZeroView::from_slice(vars.get_local_values());
            let modulus = bn254_base_modulus_packfield();
            let a_mul_b = pol_mul_wide(view.a.value, view.b.value);
            let mut c = [P::ZEROS; 2 * N_LIMBS - 1];
            c[0..N_LIMBS].copy_from_slice(&view.c.value);
            let diff = pol_sub_normal(a_mul_b, c);
            eval_modulus_zero(yield_constr, view.filter, modulus, diff, view.aux);
        }

        fn eval_ext_circuit(
            &self,
            builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
            vars: &Self::EvaluationFrameTarget,
            yield_constr: &mut starky::constraint_consumer::RecursiveConstraintConsumer<F, D>,
        ) {
            let view = ModZeroView::from_slice(vars.get_local_values());
            let modulus = bn254_base_modulus_extension_target(builder);
            let a_mul_b = pol_mul_wide_ext_circuit(builder, view.a.value, view.b.value);
            let zero = builder.zero_extension();
            let mut c = [zero; 2 * N_LIMBS - 1];
            c[0..N_LIMBS].copy_from_slice(&view.c.value);
            let diff = pol_sub_normal_ext_circuit(builder, a_mul_b, c);
            eval_modulus_zero_circuit(builder, yield_constr, view.filter, modulus, diff, view.aux);
        }

        fn constraint_degree(&self) -> usize {
            3
        }
    }
}
