use ark_bn254::{Fq, Fr};
use num::BigUint;
use plonky2::hash::hash_types::RichField;

use crate::starks::modular::utils::bigint_to_columns;
use crate::starks::modular::utils::columns_to_bigint;

pub mod curves;
pub mod modular;
pub mod utils;

pub(crate) const N_LIMBS: usize = 16;
pub(crate) const LIMB_BITS: usize = 16;

/// 256-bit value. Each element is non-negative and less than 2^LIMB_BITS.
#[derive(Clone, Copy, Debug, Default)]
pub struct U256<T> {
    pub value: [T; N_LIMBS],
}

impl<F: RichField> From<U256<F>> for Fq {
    fn from(value: U256<F>) -> Self {
        let column = value.value.map(|x| x.to_canonical_u64() as i64);
        let x = columns_to_bigint(&column);
        x.to_biguint().unwrap().into()
    }
}

impl<F: RichField> From<U256<F>> for Fr {
    fn from(value: U256<F>) -> Self {
        let column = value.value.map(|x| x.to_canonical_u64() as i64);
        let x = columns_to_bigint(&column);
        x.to_biguint().unwrap().into()
    }
}

impl<F: RichField> From<Fq> for U256<F> {
    fn from(value: Fq) -> Self {
        let x = BigUint::from(value);
        let column = bigint_to_columns(&x.into());
        U256 {
            value: column.map(|x| F::from_canonical_u64(x as u64)),
        }
    }
}

impl<F: RichField> U256<F> {
    pub(crate) fn to_i64(&self) -> U256<i64> {
        U256 {
            value: self.value.map(|x| x.to_canonical_u64() as i64),
        }
    }
}
