pub mod modular;

pub(crate) const N_LIMBS: usize = 16;
pub(crate) const LIMB_BITS: usize = 16;

/// 256-bit value. Each element is non-negative and less than 2^LIMB_BITS.
pub struct U256<T: Copy + Clone + Default> {
    pub value: [T; N_LIMBS],
}

/// Unmodded value. Each element may be less than 0 or exceed LIMB_BITS.
pub(crate) struct UnmoddedValue<T: Copy + Clone + Default> {
    pub(crate) value: [T; 2 * N_LIMBS - 1],
}
