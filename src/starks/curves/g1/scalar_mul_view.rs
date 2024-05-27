use std::ops::Range;

use crate::starks::curves::common::round_flags::{RoundFlags, ROUND_FLAGS_LEN};

use super::{
    add::{G1AddAux, G1_ADD_AUX_LEN},
    G1, G1_LEN,
};

pub(super) const PERIOD: usize = 2 * N_BITS;

pub(super) const N_BITS: usize = 256;
pub(super) const G1_SCALAR_MUL_VIEW_LEN: usize =
    5 * G1_LEN + G1_ADD_AUX_LEN + N_BITS + ROUND_FLAGS_LEN + 5;

// range check columns
pub(super) const FREQ_COL: usize = G1_SCALAR_MUL_VIEW_LEN - 2;
pub(super) const RANGE_COUNTER_COL: usize = G1_SCALAR_MUL_VIEW_LEN - 1;
pub(super) const RANGE_CHECK_COLS: Range<usize> = 2 * G1_LEN..4 * G1_LEN + G1_ADD_AUX_LEN;
pub(super) const NUM_RANGE_CHECK_COLS: usize = RANGE_CHECK_COLS.end - RANGE_CHECK_COLS.start;

// CTL columns
pub(super) const DOUBLE_COLS: Range<usize> = 0..G1_LEN;
pub(super) const SUM_COLS: Range<usize> = G1_LEN..2 * G1_LEN;
pub(super) const A_COLS: Range<usize> = 2 * G1_LEN..3 * G1_LEN;
pub(super) const B_COLS: Range<usize> = 3 * G1_LEN..4 * G1_LEN;
pub(super) const C_COLS: Range<usize> = 4 * G1_LEN..5 * G1_LEN;
pub(super) const BITS_COLS: Range<usize> =
    5 * G1_LEN + G1_ADD_AUX_LEN..5 * G1_LEN + G1_ADD_AUX_LEN + N_BITS;
pub(super) const INPUT_FILTER_COL: usize = 5 * G1_LEN + G1_ADD_AUX_LEN + N_BITS;
pub(super) const OUTPUT_FILTER_COL: usize = INPUT_FILTER_COL + 1;
pub(super) const TIMESTAMP_COL: usize = 5 * G1_LEN + G1_ADD_AUX_LEN + N_BITS + ROUND_FLAGS_LEN;

#[repr(C)]
#[derive(Clone, Debug)]
pub(super) struct G1ScalarMulView<F: Copy + Clone + Default> {
    pub(super) double: G1<F>,              // stores the doubles of `x`
    pub(super) sum: G1<F>,                 // running sum
    pub(super) a: G1<F>,                   // add register a
    pub(super) b: G1<F>,                   // add register b
    pub(super) c: G1<F>,                   // add register c
    pub(super) add_aux: G1AddAux<F>,       // aux for add
    pub(super) bits: [F; N_BITS],          // bits of the scalar rotates to the left in each row
    pub(super) round_flags: RoundFlags<F>, // first and last round flags
    pub(super) timestamp: F,               // timestamp for ctl
    pub(super) is_even: F,                 // is_even
    pub(super) filter: F,                  // filter of scalar multiplication constraint
    pub(super) frequency: F,               // frequency colum for range check
    pub(super) range_counter: F,           // counter for range check
}

impl<F: Copy + Clone + Default> Default for G1ScalarMulView<F> {
    fn default() -> Self {
        Self {
            double: G1::default(),
            sum: G1::default(),
            a: G1::default(),
            b: G1::default(),
            c: G1::default(),
            add_aux: G1AddAux::default(),
            bits: [F::default(); N_BITS],
            round_flags: RoundFlags::default(),
            timestamp: F::default(),
            is_even: F::default(),
            filter: F::default(),
            frequency: F::default(),
            range_counter: F::default(),
        }
    }
}

impl<T: Copy + Clone + Default> G1ScalarMulView<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        unsafe {
            std::slice::from_raw_parts(self as *const Self as *const T, G1_SCALAR_MUL_VIEW_LEN)
        }
    }
    pub(super) fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), G1_SCALAR_MUL_VIEW_LEN);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}

#[cfg(test)]
mod tests {

    use crate::starks::curves::g1::scalar_mul_view::{
        INPUT_FILTER_COL, OUTPUT_FILTER_COL, TIMESTAMP_COL,
    };

    use super::G1ScalarMulView;

    #[test]
    fn row_position_correctness() {
        // ctl related columns
        {
            let mut view = G1ScalarMulView::<u64>::default();
            view.round_flags.is_first_round = 1;
            view.round_flags.is_last_round = 2;
            view.timestamp = 3;
            assert_eq!(view.to_slice()[INPUT_FILTER_COL], 1);
            assert_eq!(view.to_slice()[OUTPUT_FILTER_COL], 2);
            assert_eq!(view.to_slice()[TIMESTAMP_COL], 3);
        }
    }
}
