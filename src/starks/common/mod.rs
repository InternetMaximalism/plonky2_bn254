pub(crate) mod ctl_values;
pub(crate) mod eq;
// SECURITY NOTE: the manual multi-stark prover/verifier wrappers below have
// not yet been migrated to plonky2 1.x's starky CTL API (signature changes,
// removed `CtlCheckVars::from_proofs`, new `degree_bits` field on
// StarkProofTarget, etc.). Gated behind
// `cfg(not(feature = "not-constrain-bn254-stark"))` so the gadget API still
// compiles. With the feature on, callers get **no in-circuit STARK proof**
// of g1/g2/fq correctness — a malicious prover can lie about the outputs.
#[cfg(not(feature = "not-constrain-bn254-stark"))]
pub(crate) mod prover;
pub(crate) mod round_flags;
pub(crate) mod utils;
#[cfg(not(feature = "not-constrain-bn254-stark"))]
pub(crate) mod verifier;
