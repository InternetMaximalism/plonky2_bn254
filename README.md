# plonky2_bn254

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Overview

This repository primarily focuses on the starky implementation of scalar multiplication on the bn254 curve, and provides various utility functions for elliptic curves on the bn254 curve.

## Usage

### g1 scalar multiplication

```rust
let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
let scalar = builder.add_virtual_biguint_target(8);
let x = G1Target::new_checked(&mut builder);
let offset = G1Target::new_checked(&mut builder);
let output = builder.g1_scalar_mul::<C>(scalar, x, offset);
```

### g2 scalar multiplication

```rust
let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
let scalar = builder.add_virtual_biguint_target(8);
let x = FqTarget::new_checked(&mut builder);
let offset = G2Target::new_checked(&mut builder);
let output = builder.g2_scalar_mul::<C>(scalar, x, offset);
```

### fq exponentiation

```rust
let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
let scalar = builder.add_virtual_biguint_target(8);
let x = FqTarget::new_checked(&mut builder);
let output = builder.fq_exp::<C>(s, x)
```

### map from fq2 to g2

```rust
let mut builder = CircuitBuilder::<F, D>::new(config);
let input_t = Fq2Target::constant(&mut builder, &input);
let output_t = G2Target::map_to_g2_circuit::<C>(&mut builder, &input_t);
```

## License

This project is licensed under the [MIT License](LICENSE).
