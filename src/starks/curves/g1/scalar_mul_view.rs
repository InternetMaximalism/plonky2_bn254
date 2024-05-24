use crate::starks::curves::common::round_flags::{RoundFlags, ROUND_FLAGS_LEN};

use super::{
    add::{G1AddAux, G1_ADD_AUX_LEN},
    G1, G1_LEN,
};

pub(crate) const N_BITS: usize = 256;
pub(crate) const G1_SCALAR_MUL_VIEW_LEN: usize =
    3 * G1_LEN + 2 * G1_ADD_AUX_LEN + N_BITS + 1 + ROUND_FLAGS_LEN + 3;

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct G1ScalarMulView<F: Copy + Clone + Default> {
    pub(crate) double: G1<F>,              // next.double = 2*local.double
    pub(crate) double_aux: G1AddAux<F>,    // aux for double
    pub(crate) prev_sum: G1<F>,            // next.prev_sum = local.sum
    pub(crate) sum: G1<F>,                 // local.sum = prev_sum + bit_filtered * double
    pub(crate) sum_aux: G1AddAux<F>,       // aux for sum
    pub(crate) bits: [F; N_BITS],          // bits of the scalar rotates to the left in each row
    pub(crate) timestamp: F,               // timestamp for ctl
    pub(crate) round_flags: RoundFlags<F>, // first and last round flags
    pub(crate) filter: F,                  // filter of scalar multiplication constraint
    pub(crate) frequency: F,               // frequency colum for range check
    pub(crate) range_counter: F,           // counter for range check
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
    pub(crate) fn to_slice(&self) -> &[T] {
        unsafe {
            std::slice::from_raw_parts(self as *const Self as *const T, G1_SCALAR_MUL_VIEW_LEN)
        }
    }
    pub(crate) fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), G1_SCALAR_MUL_VIEW_LEN);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}
