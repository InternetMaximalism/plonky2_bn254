use itertools::Itertools;
use plonky2::{
    field::{
        extension::Extendable,
        packed::PackedField,
        types::{Field, PrimeField64},
    },
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

use super::{
    add::{G2AddAux, G2_ADD_AUX_LEN},
    scalar_mul_view::G2ScalarMulView,
    G2, G2_LEN,
};

const RANGE_CHECK_TARGET_LEN: usize = 3 * G2_LEN + G2_ADD_AUX_LEN;
pub(super) const NUM_DECOMPOSED_COLS: usize = 2 * RANGE_CHECK_TARGET_LEN;

#[repr(C)]
#[derive(Clone, Debug)]
struct RangeCheckTarget<F: Copy + Clone + Default> {
    a: G2<F>,
    b: G2<F>,
    c: G2<F>,
    add_aux: G2AddAux<F>,
}

impl<T: Copy + Clone + Default> RangeCheckTarget<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        debug_assert_eq!(
            std::mem::size_of::<Self>(),
            RANGE_CHECK_TARGET_LEN * std::mem::size_of::<T>()
        );
        unsafe {
            std::slice::from_raw_parts(self as *const Self as *const T, RANGE_CHECK_TARGET_LEN)
        }
    }
    fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), RANGE_CHECK_TARGET_LEN);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}

pub(super) fn fill_decomposed_cols<F: PrimeField64>(local: &mut G2ScalarMulView<F>) {
    let target = RangeCheckTarget {
        a: local.a,
        b: local.b,
        c: local.c,
        add_aux: local.add_aux,
    };
    let decomposed_cols = target
        .to_slice()
        .into_iter()
        .flat_map(|x| {
            let x = x.to_canonical_u64();
            assert!(x < 1 << 16);
            let x_lo: u8 = x as u8;
            let x_hi = (x >> 8) as u8;
            vec![F::from_canonical_u8(x_lo), F::from_canonical_u8(x_hi)]
        })
        .collect::<Vec<_>>();
    local.decomposed_cols = decomposed_cols.try_into().unwrap();
}

pub(super) fn eval_decomposition<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    local: &G2ScalarMulView<P>,
) {
    let target = RangeCheckTarget {
        a: local.a,
        b: local.b,
        c: local.c,
        add_aux: local.add_aux,
    };

    local
        .decomposed_cols
        .into_iter()
        .chunks(2)
        .into_iter()
        .zip(target.to_slice().into_iter())
        .for_each(|(decomposed, x)| {
            let decomposed = decomposed.collect::<Vec<_>>();
            let base: P = P::Scalar::from_canonical_u64(1 << 8).into();
            let x_composed = decomposed[1].clone() * base + decomposed[0].clone();
            yield_constr.constraint(local.filter * (*x - x_composed));
        });
}

pub(super) fn eval_decomposition_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    local: &G2ScalarMulView<ExtensionTarget<D>>,
) {
    let target = RangeCheckTarget {
        a: local.a,
        b: local.b,
        c: local.c,
        add_aux: local.add_aux,
    };
    local
        .decomposed_cols
        .into_iter()
        .chunks(2)
        .into_iter()
        .zip(target.to_slice().into_iter())
        .for_each(|(decomposed, x)| {
            let decomposed = decomposed.collect::<Vec<_>>();
            let base = builder.constant_extension(F::Extension::from_canonical_u64(1 << 8));
            let x_composed = builder.mul_add_extension(decomposed[1], base, decomposed[0]);
            let x_diff = builder.sub_extension(*x, x_composed);
            let x_diff_filtered = builder.mul_extension(local.filter, x_diff);
            yield_constr.constraint(builder, x_diff_filtered);
        });
}
