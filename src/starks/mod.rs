use ark_bn254::Fq;
use num::BigUint;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::vars;

use crate::starks::modular::utils::bigint_to_columns;
use crate::starks::modular::utils::columns_to_bigint;

pub(crate) mod common;
pub(crate) mod curves;
pub(crate) mod modular;
pub(crate) mod utils;

pub(crate) const N_LIMBS: usize = 16;
pub(crate) const LIMB_BITS: usize = 16;

/// 256-bit value. Each element is non-negative and less than 2^LIMB_BITS.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct U256<T> {
    pub value: [T; N_LIMBS],
}

impl<T: Copy + Clone + Default> U256<T> {
    pub(super) fn to_slice(&self) -> &[T] {
        debug_assert_eq!(
            std::mem::size_of::<Self>(),
            N_LIMBS * std::mem::size_of::<T>()
        );
        unsafe { std::slice::from_raw_parts(self as *const Self as *const T, N_LIMBS) }
    }
    pub(super) fn from_slice(slice: &[T]) -> &Self {
        assert_eq!(slice.len(), N_LIMBS);
        unsafe { &*(slice.as_ptr() as *const Self) }
    }
}

impl<F: RichField> From<U256<F>> for Fq {
    fn from(value: U256<F>) -> Self {
        let column = value.value.map(|x| x.to_canonical_u64() as i64);
        let x = columns_to_bigint(&column);
        x.to_biguint().unwrap().into()
    }
}

impl<F: RichField> From<U256<F>> for BigUint {
    fn from(value: U256<F>) -> Self {
        let column = value.value.map(|x| x.to_canonical_u64() as i64);
        let x = columns_to_bigint(&column);
        x.to_biguint().unwrap()
    }
}

impl<F: RichField> From<BigUint> for U256<F> {
    fn from(value: BigUint) -> Self {
        let column = bigint_to_columns(&value.into());
        U256 {
            value: column.map(|x| F::from_canonical_u64(x as u64)),
        }
    }
}

impl<F: RichField> From<Fq> for U256<F> {
    fn from(value: Fq) -> Self {
        BigUint::from(value).into()
    }
}

impl<F: RichField> U256<F> {
    pub(crate) fn to_i64(&self) -> U256<i64> {
        U256 {
            value: self.value.map(|x| x.to_canonical_u64() as i64),
        }
    }

    pub(crate) fn to_u16(&self) -> U256<u16> {
        U256 {
            value: self.value.map(|x| {
                assert!(x.to_canonical_u64() < 1 << 16);
                x.to_canonical_u64() as u16
            }),
        }
    }
}
