use std::ops::Range;

use crate::starks::{
    common::round_flags::{RoundFlags, ROUND_FLAGS_LEN},
    modular::modulus_zero::{ModulusZeroAux, MODULUS_AUX_ZERO_LEN},
    N_LIMBS, U256,
};

pub(crate) const FQ_PERIOD: usize = 2 * N_BITS;

pub(super) const N_BITS: usize = 256;
pub(super) const FQ_EXP_VIEW_LEN: usize =
    5 * N_LIMBS + MODULUS_AUX_ZERO_LEN + N_BITS + ROUND_FLAGS_LEN + 6;

// range check columns
pub(super) const FREQ_COL: usize = FQ_EXP_VIEW_LEN - 2;
pub(super) const RANGE_COUNTER_COL: usize = FQ_EXP_VIEW_LEN - 1;
pub(super) const RANGE_CHECK_COLS: Range<usize> = 2 * N_LIMBS..5 * N_LIMBS + MODULUS_AUX_ZERO_LEN;
pub(super) const NUM_RANGE_CHECK_COLS: usize = RANGE_CHECK_COLS.end - RANGE_CHECK_COLS.start;

// CTL columns
pub(super) const PRODUCT_COLS: Range<usize> = N_LIMBS..2 * N_LIMBS;
pub(super) const B_COLS: Range<usize> = 3 * N_LIMBS..4 * N_LIMBS;
pub(super) const BITS_COLS: Range<usize> =
    5 * N_LIMBS + MODULUS_AUX_ZERO_LEN..5 * N_LIMBS + MODULUS_AUX_ZERO_LEN + N_BITS;
pub(super) const INPUT_FILTER_COL: usize = 5 * N_LIMBS + MODULUS_AUX_ZERO_LEN + N_BITS;
pub(super) const OUTPUT_FILTER_COL: usize = INPUT_FILTER_COL + 1;
pub(super) const TIMESTAMP_COL: usize =
    5 * N_LIMBS + MODULUS_AUX_ZERO_LEN + N_BITS + ROUND_FLAGS_LEN;

#[repr(C)]
#[derive(Clone, Debug)]
pub(super) struct FqExpView<F: Copy + Clone + Default> {
    pub(super) square: U256<F>,            // stores the squares of `x`
    pub(super) product: U256<F>,           // running product
    pub(super) a: U256<F>,                 // add register a
    pub(super) b: U256<F>,                 // add register b
    pub(super) c: U256<F>,                 // add register c
    pub(super) mul_aux: ModulusZeroAux<F>, // aux for mul
    pub(super) bits: [F; N_BITS],          // bits of the scalar rotates to the left in each row
    pub(super) round_flags: RoundFlags<F>, // first and last round flags
    pub(super) timestamp: F,               // timestamp for ctl
    pub(super) is_mul: F,                  // is mul
    pub(super) is_sq_not_last: F,          // is sq and not last round
    pub(super) filter: F,                  // filter of scalar multiplication constraint
    pub(super) frequency: F,               // frequency colum for range check
    pub(super) range_counter: F,           // counter for range check
}

impl<F: Copy + Clone + Default> Default for FqExpView<F> {
    fn default() -> Self {
        Self {
            square: U256::default(),
            product: U256::default(),
            a: U256::default(),
            b: U256::default(),
            c: U256::default(),
            mul_aux: ModulusZeroAux::default(),
            bits: [F::default(); N_BITS],
            round_flags: RoundFlags::default(),
            timestamp: F::default(),
            is_mul: F::default(),
            is_sq_not_last: F::default(),
            filter: F::default(),
            frequency: F::default(),
            range_counter: F::default(),
        }
    }
}

impl<T: Copy + Clone + Default> FqExpView<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        debug_assert_eq!(
            std::mem::size_of::<Self>(),
            FQ_EXP_VIEW_LEN * std::mem::size_of::<T>()
        );
        unsafe { std::slice::from_raw_parts(self as *const Self as *const T, FQ_EXP_VIEW_LEN) }
    }
    pub(super) fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), FQ_EXP_VIEW_LEN);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_position_correctness() {
        // ctl related columns
        {
            let mut view = FqExpView::<u64>::default();
            view.round_flags.is_first_round = 1;
            view.round_flags.is_last_round = 2;
            view.timestamp = 3;
            assert_eq!(view.to_slice()[INPUT_FILTER_COL], 1);
            assert_eq!(view.to_slice()[OUTPUT_FILTER_COL], 2);
            assert_eq!(view.to_slice()[TIMESTAMP_COL], 3);
        }
        // range check columns
        {
            let mut view = FqExpView::<u64>::default();
            view.frequency = 1;
            view.range_counter = 2;
            assert_eq!(view.to_slice()[FREQ_COL], 1);
            assert_eq!(view.to_slice()[RANGE_COUNTER_COL], 2);
        }
    }
}
