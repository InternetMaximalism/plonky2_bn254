use std::ops::Range;

use crate::starks::common::round_flags::{RoundFlags, ROUND_FLAGS_LEN};

use super::{
    add::{G2AddAux, G2_ADD_AUX_LEN},
    G2, G2_LEN,
};

pub(crate) const G2_PERIOD: usize = 2 * N_BITS;

pub(super) const N_BITS: usize = 256;
pub(super) const G2_SCALAR_MUL_VIEW_LEN: usize =
    5 * G2_LEN + G2_ADD_AUX_LEN + N_BITS + ROUND_FLAGS_LEN + 6;

// range check columns
pub(super) const FREQ_COL: usize = G2_SCALAR_MUL_VIEW_LEN - 2;
pub(super) const RANGE_COUNTER_COL: usize = G2_SCALAR_MUL_VIEW_LEN - 1;
pub(super) const RANGE_CHECK_COLS: Range<usize> = 2 * G2_LEN..5 * G2_LEN + G2_ADD_AUX_LEN;
pub(super) const NUM_RANGE_CHECK_COLS: usize = RANGE_CHECK_COLS.end - RANGE_CHECK_COLS.start;

// CTL columns
pub(super) const SUM_COLS: Range<usize> = G2_LEN..2 * G2_LEN;
pub(super) const A_COLS: Range<usize> = 2 * G2_LEN..3 * G2_LEN;
pub(super) const B_COLS: Range<usize> = 3 * G2_LEN..4 * G2_LEN;
pub(super) const BITS_COLS: Range<usize> =
    5 * G2_LEN + G2_ADD_AUX_LEN..5 * G2_LEN + G2_ADD_AUX_LEN + N_BITS;
pub(super) const INPUT_FILTER_COL: usize = 5 * G2_LEN + G2_ADD_AUX_LEN + N_BITS;
pub(super) const OUTPUT_FILTER_COL: usize = INPUT_FILTER_COL + 1;
pub(super) const TIMESTAMP_COL: usize = 5 * G2_LEN + G2_ADD_AUX_LEN + N_BITS + ROUND_FLAGS_LEN;

#[repr(C)]
#[derive(Clone, Debug)]
pub(super) struct G2ScalarMulView<F: Copy + Clone + Default> {
    pub(super) double: G2<F>,              // stores the doubles of `x`
    pub(super) sum: G2<F>,                 // running sum
    pub(super) a: G2<F>,                   // add register a
    pub(super) b: G2<F>,                   // add register b
    pub(super) c: G2<F>,                   // add register c
    pub(super) add_aux: G2AddAux<F>,       // aux for add
    pub(super) bits: [F; N_BITS],          // bits of the scalar rotates to the left in each row
    pub(super) round_flags: RoundFlags<F>, // first and last round flags
    pub(super) timestamp: F,               // timestamp for ctl
    pub(super) is_adding: F,               // is adding
    pub(super) is_doubling_not_last: F,    // is doubling and not last round
    pub(super) filter: F,                  // filter of scalar multiplication constraint
    pub(super) frequency: F,               // frequency colum for range check
    pub(super) range_counter: F,           // counter for range check
}

impl<F: Copy + Clone + Default> Default for G2ScalarMulView<F> {
    fn default() -> Self {
        Self {
            double: G2::default(),
            sum: G2::default(),
            a: G2::default(),
            b: G2::default(),
            c: G2::default(),
            add_aux: G2AddAux::default(),
            bits: [F::default(); N_BITS],
            round_flags: RoundFlags::default(),
            timestamp: F::default(),
            is_adding: F::default(),
            is_doubling_not_last: F::default(),
            filter: F::default(),
            frequency: F::default(),
            range_counter: F::default(),
        }
    }
}

impl<T: Copy + Clone + Default> G2ScalarMulView<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        debug_assert_eq!(
            std::mem::size_of::<Self>(),
            G2_SCALAR_MUL_VIEW_LEN * std::mem::size_of::<T>()
        );
        unsafe {
            std::slice::from_raw_parts(self as *const Self as *const T, G2_SCALAR_MUL_VIEW_LEN)
        }
    }
    pub(super) fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), G2_SCALAR_MUL_VIEW_LEN);
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
            let mut view = G2ScalarMulView::<u64>::default();
            view.round_flags.is_first_round = 1;
            view.round_flags.is_last_round = 2;
            view.timestamp = 3;
            assert_eq!(view.to_slice()[INPUT_FILTER_COL], 1);
            assert_eq!(view.to_slice()[OUTPUT_FILTER_COL], 2);
            assert_eq!(view.to_slice()[TIMESTAMP_COL], 3);
        }
        // range check columns
        {
            let mut view = G2ScalarMulView::<u64>::default();
            view.frequency = 1;
            view.range_counter = 2;
            assert_eq!(view.to_slice()[FREQ_COL], 1);
            assert_eq!(view.to_slice()[RANGE_COUNTER_COL], 2);
        }
    }
}
