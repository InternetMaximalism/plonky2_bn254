use super::{
    add::{G1AddAux, G1_ADD_AUX_LEN},
    G1, G1_LEN,
};

pub(crate) const N_BITS: usize = 256;
pub(crate) const G1_SCALAR_MUL_VIEW_LEN: usize =
    2 * G1_LEN + 2 * N_BITS + 1 + 2 * G1_ADD_AUX_LEN + 1;

#[repr(C)]
#[derive(Clone)]
pub(crate) struct G1ScalarMulView<F: Copy + Clone + Default> {
    double: G1<F>,
    sum: G1<F>,
    bits: [F; N_BITS],
    round_flags: [F; N_BITS],
    timestamp: F,
    double_aux: G1AddAux<F>,
    sum_aux: G1AddAux<F>,
    frequency: F, // frequency colum for range check
    range: F,     // simple counter for range check
    filter: F,
}

impl<F: Copy + Clone + Default> Default for G1ScalarMulView<F> {
    fn default() -> Self {
        Self {
            double: G1::default(),
            sum: G1::default(),
            bits: [F::default(); N_BITS],
            round_flags: [F::default(); N_BITS],
            timestamp: F::default(),
            double_aux: G1AddAux::default(),
            sum_aux: G1AddAux::default(),
            frequency: F::default(),
            range: F::default(),
            filter: F::default(),
        }
    }
}

impl<T: Copy + Clone + Default> G1ScalarMulView<T> {
    fn to_slice(&self) -> &[T] {
        unsafe {
            std::slice::from_raw_parts(self as *const Self as *const T, G1_SCALAR_MUL_VIEW_LEN)
        }
    }
    fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), G1_SCALAR_MUL_VIEW_LEN);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}
