use std::ops::Range;

use crate::starks::curves::common::round_flags::{RoundFlags, ROUND_FLAGS_LEN};

use super::{
    add::{G1AddAux, G1_ADD_AUX_LEN},
    G1, G1_LEN,
};

pub(super) const N_BITS: usize = 256;
pub(super) const G1_SCALAR_MUL_VIEW_LEN: usize =
    3 * G1_LEN + 2 * G1_ADD_AUX_LEN + N_BITS + 1 + ROUND_FLAGS_LEN + 3;

// range check columns
pub(super) const FREQ_COL: usize = G1_SCALAR_MUL_VIEW_LEN - 2;
pub(super) const RANGE_COUNTER_COL: usize = G1_SCALAR_MUL_VIEW_LEN - 1;
pub(super) const RANGE_CHECK_COLS: Range<usize> = 0..3 * G1_LEN + 2 * G1_ADD_AUX_LEN;
pub(super) const NUM_RANGE_CHECK_COLS: usize = 3 * G1_LEN + 2 * G1_ADD_AUX_LEN;

// CTL columns
pub(super) const DOUBLE_COLS: Range<usize> = 0..G1_LEN;
pub(super) const PREV_SUM_COLS: Range<usize> = G1_LEN + G1_ADD_AUX_LEN..2 * G1_LEN + G1_ADD_AUX_LEN;
pub(super) const SUM_COLS: Range<usize> = 2 * G1_LEN + G1_ADD_AUX_LEN..3 * G1_LEN + G1_ADD_AUX_LEN;
pub(super) const BITS_COLS: Range<usize> =
    3 * G1_LEN + 2 * G1_ADD_AUX_LEN..3 * G1_LEN + 2 * G1_ADD_AUX_LEN + N_BITS;
pub(super) const TIMESTAMP_COL: usize = 3 * G1_LEN + 2 * G1_ADD_AUX_LEN + N_BITS;
pub(super) const INPUT_FILTER_COL: usize = TIMESTAMP_COL + 1;
pub(super) const OUTPUT_FILTER_COL: usize = INPUT_FILTER_COL + 1;

#[repr(C)]
#[derive(Clone, Debug)]
pub(super) struct G1ScalarMulView<F: Copy + Clone + Default> {
    pub(super) double: G1<F>,              // next.double = 2*local.double
    pub(super) double_aux: G1AddAux<F>,    // aux for double
    pub(super) prev_sum: G1<F>,            // next.prev_sum = local.sum
    pub(super) sum: G1<F>,                 // local.sum = prev_sum + bit_filtered * double
    pub(super) sum_aux: G1AddAux<F>,       // aux for sum
    pub(super) bits: [F; N_BITS],          // bits of the scalar rotates to the left in each row
    pub(super) timestamp: F,               // timestamp for ctl
    pub(super) round_flags: RoundFlags<F>, // first and last round flags
    pub(super) filter: F,                  // filter of scalar multiplication constraint
    pub(super) frequency: F,               // frequency colum for range check
    pub(super) range_counter: F,           // counter for range check
}

impl<F: Copy + Clone + Default> Default for G1ScalarMulView<F> {
    fn default() -> Self {
        Self {
            double: G1::default(),
            double_aux: G1AddAux::default(),
            prev_sum: G1::default(),
            sum: G1::default(),
            sum_aux: G1AddAux::default(),
            bits: [F::default(); N_BITS],
            timestamp: F::default(),
            round_flags: RoundFlags::default(),
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
