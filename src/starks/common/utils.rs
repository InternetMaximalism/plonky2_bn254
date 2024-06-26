use num::BigUint;

pub(crate) fn biguint_to_le_bits(n: &BigUint, len: usize) -> Vec<bool> {
    assert!(n.bits() <= len as u64);
    let mut result = Vec::new();
    let bytes = n.to_bytes_le(); // Little endian byte order
    for byte in bytes {
        for i in 0..8 {
            result.push((byte & (1 << i)) != 0);
        }
    }
    result.resize(len, false);
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use num::BigUint;
    use rand::Rng;

    pub(crate) fn random_biguint<R: Rng>(rng: &mut R) -> BigUint {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        BigUint::from_bytes_le(&bytes)
    }
}
