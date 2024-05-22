use ark_bn254::Fq;
use num::{BigInt, BigUint, FromPrimitive as _};

pub(crate) fn bn254_base_modulus_bigint() -> BigInt {
    let neg_one: BigUint = Fq::from(-1).into();
    let modulus_biguint: BigUint = neg_one + BigUint::from_usize(1).unwrap();
    let modulus_bigint: BigInt = modulus_biguint.into();
    modulus_bigint
}
