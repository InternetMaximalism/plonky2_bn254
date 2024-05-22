use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use crate::starks::{LIMB_BITS, U256};

/// 2^{-LIMB_BITS} mod goldilocks
const GOLDILOCKS_INVERSE_65536: u64 = 18446462594437939201;

/// Constraint that x + y = z + 2^256*cy and cy=0 or 1 where cy is the carry.
pub(crate) fn eval_packed_generic_addcy<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    filter: P,
    x: U256<P>,
    y: U256<P>,
    z: U256<P>,
    given_cy: P,
) {
    let overflow = P::Scalar::from_canonical_u64(1u64 << LIMB_BITS);
    let overflow_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_65536);
    assert!(
        overflow * overflow_inv == P::Scalar::ONE,
        "only works with LIMB_BITS=16 and F=Goldilocks"
    );
    let mut cy = P::ZEROS;
    for ((&xi, &yi), &zi) in x.value.iter().zip_eq(y.value.iter()).zip_eq(z.value.iter()) {
        // Verify that (xi + yi) - zi is either 0 or 2^LIMB_BITS
        let t = cy + xi + yi - zi;
        yield_constr.constraint(filter * t * (overflow - t));
        cy = t * overflow_inv;
    }
    yield_constr.constraint(filter * given_cy * (given_cy - P::ONES));
    yield_constr.constraint(filter * (cy - given_cy));
}

#[allow(clippy::needless_collect)]
pub(crate) fn eval_ext_circuit_addcy<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    filter: ExtensionTarget<D>,
    x: U256<ExtensionTarget<D>>,
    y: U256<ExtensionTarget<D>>,
    z: U256<ExtensionTarget<D>>,
    given_cy: ExtensionTarget<D>,
) {
    // 2^LIMB_BITS in the base field
    let overflow_base = F::from_canonical_u64(1 << LIMB_BITS);
    // 2^LIMB_BITS in the extension field as an ExtensionTarget
    let overflow = builder.constant_extension(F::Extension::from(overflow_base));
    // 2^-LIMB_BITS in the base field.
    let overflow_inv = F::from_canonical_u64(GOLDILOCKS_INVERSE_65536);

    let mut cy = builder.zero_extension();
    for ((&xi, &yi), &zi) in x.value.iter().zip_eq(y.value.iter()).zip_eq(z.value.iter()) {
        // t0 = cy + xi + yi
        let t0 = builder.add_many_extension([cy, xi, yi]);
        // t  = t0 - zi
        let t = builder.sub_extension(t0, zi);
        // t1 = overflow - t
        let t1 = builder.sub_extension(overflow, t);
        // t2 = t * t1
        let t2 = builder.mul_extension(t, t1);

        let filtered_limb_constraint = builder.mul_extension(filter, t2);

        yield_constr.constraint(builder, filtered_limb_constraint);

        cy = builder.mul_const_extension(overflow_inv, t);
    }

    let good_cy = builder.sub_extension(cy, given_cy);
    let cy_filter = builder.mul_extension(filter, good_cy);

    // Check given carry is one bit
    let bit_constr = builder.mul_sub_extension(given_cy, given_cy, given_cy);
    let bit_filter = builder.mul_extension(filter, bit_constr);

    yield_constr.constraint(builder, bit_filter);
    yield_constr.constraint(builder, cy_filter);
}
