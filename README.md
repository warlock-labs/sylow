![Logo](./sylow.png)

[![License](https://img.shields.io/crates/l/sylow)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/sylow)](https://crates.io/crates/sylow)
[![Docs](https://img.shields.io/crates/v/sylow?color=blue&label=docs)](https://docs.rs/sylow/)
![CI](https://github.com/warlock-labs/sylow/actions/workflows/CI.yml/badge.svg)

Sylow (*ˈsyːlɔv*) is a comprehensive Rust library for elliptic curve cryptography, specifically tailored for the BN254 
(alt-bn128) curve. It provides a robust implementation of finite fields, elliptic curve groups, and pairing-based 
cryptography, making it an ideal choice for applications in blockchain, zero-knowledge proofs, and other cryptographic 
systems.

## Features

- **Finite Field Arithmetic**: Efficient implementations of prime fields and their extensions $\mathbb{F}_ {p}, \mathbb
  {F}_ {p^2}, 
  \mathbb{F}_ {p^6}, 
  \mathbb{F}_{p^{12}}$
- **Elliptic Curve Groups**: Complete support for operations on $\mathbb{G}_ 1$, $\mathbb{G}_  2$, and $\mathbb{G}_{\rm 
  T}$ groups of the BN254 curve
- **Pairing Operations**: Optimized implementation of the optimal ate pairing
- **Cryptographic Primitives**:
  - Key generation 
  - BLS signature generation and verification
  - Hash-to-curve functionality
- **Auxiliary Cryptographic Functions**:
  - Pseudo-random number generation
  - Constant-time operations for enhanced security
- **Compatibility**: Designed to be compatible with Ethereum's precompiled contracts for BN254 operations.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sylow = "0.0.1"
```

Here's a basic example demonstrating key generation, signing, and verification:

```rust
use sylow::{KeyPair, sign, verify};

fn main() {
  // Generate a new key pair
  let key_pair = KeyPair::generate();

  // Message to be signed
  let message = b"Hello, Sylow!";

  // Sign the message
  match sign(&key_pair.secret_key, message) {
    Ok(signature) => {
      // Verify the signature
      match verify(&key_pair.public_key, message, &signature) {
        Ok(is_valid) => {
          assert!(is_valid, "Signature verification failed");
          println!("Signature verified successfully!");
        },
        Err(e) => println!("Verification error: {:?}", e),
      }
    },
    Err(e) => println!("Signing error: {:?}", e),
  }
}
```

For more, please see [the examples](https://github.com/warlock-labs/sylow/tree/main/examples), and for 
advanced usage details, see the [API documentation](https://docs.rs/sylow).

## Core Concepts

- **Finite fields**: The foundation of the library, providing arithmetic operations in prime fields and their extensions.
- **Elliptic Curve Groups**: Implementations of the $\mathbb{G}_ 1$, $\mathbb{G}_  2$, and $\mathbb{G}_{\rm
  T}$ groups on the BN254 curve, supporting both affine and projective coordinates.
- **Pairing**: Efficient implementation of the optimal ate pairing, crucial for many cryptographic protocols.
- **alt-bn128 (BN254) Curve**: A pairing-friendly elliptic curve widely used in zkSNARKs and supported by Ethereum precompiles.

## Advanced Features

- **Customizable Hashing**: Supports various hash functions through the `Expander` trait, such as the XMD and XOF 
  algorithms on any hasher from `sha3`.
- **Optimized Arithmetic**: Utilizes Montgomery form for efficient modular arithmetic.
- **Constant-time Operations**: Implements algorithms resistant to timing attacks.
- **Batch Verification**: Verify multiple signatures in a single operation for improved performance.

## Performance

Sylow is designed with performance in mind, leveraging optimized algorithms for finite field arithmetic, elliptic curve 
operations, and pairings, taking advantage of specialized algorithms for $j$-invariant zero curves, as well as the 
optimal ate pairing for efficient signature verification. 

## Roadmap

The following features and improvements are planned for future releases:

- [x] Basic signature implementation
- [x] Key generation utilities
- [x] Optimizations for common operations
- [x] Extended test suite and benchmarks
- [ ] Support for serialization formats used in blockchain contexts

## Contributing

We welcome contributions to Sylow! Whether it's bug reports, feature requests, or code contributions, please feel free 
to engage with the project by submitting issues, feature requests, or pull requests on the [GitHub repository]
(https://github.com/warlock-labs/sylow).

## License

This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/).

## Contact

This project is maintained by:
- Tristan Britt [tristan@warlock.xyz](mailto:tristan@warlock.xyz)
- 0xAlcibiades [alcibiades@warlock.xyz](mailto:alcibiades@warlock.xyz)

Warlock Labs - [https://github.com/warlock-labs](https://github.com/warlock-labs)

Project Link: [https://github.com/warlock-labs/sylow](https://github.com/warlock-labs/sylow)