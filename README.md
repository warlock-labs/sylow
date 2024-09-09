![Logo](./sylow.png)

# Sylow

[![Crates.io](https://img.shields.io/crates/v/sylow)](https://crates.io/crates/sylow)
[![Docs](https://img.shields.io/crates/v/sylow?color=blue&label=docs)](https://docs.rs/sylow/)
![CI](https://github.com/warlock-labs/sylow/actions/workflows/CI.yml/badge.svg)
[![codecov](https://codecov.io/gh/warlock-labs/sylow/graph/badge.svg?token=MJNRUZHI1Z)](https://codecov.io/gh/warlock-labs/sylow)

<!-- Generally seems to be pronounced SEE-low at least in American English, and perhaps note that it's being named after Ludwig. -->
Sylow (*ˈsyːlɔv*) is a comprehensive Rust library for elliptic curve cryptography, specifically tailored for the BN254 (
alt-bn128) curve. It provides a robust implementation of finite fields, elliptic curve groups, and pairing-based
cryptography, making it an ideal choice for applications in blockchain, zero-knowledge proofs, and other cryptographic
systems.

## Features

- **Finite Field Arithmetic**: Efficient implementations of prime fields and their extensions 𝔽ₚ, 𝔽ₚ², 𝔽ₚ⁶, 𝔽ₚ¹²
- **Elliptic Curve Groups**: Complete support for operations on 𝔾₁, 𝔾₂, and 𝔾ₜ groups of the BN254 curve
- **Pairing Operations**: Optimized implementation of the optimal ate pairing
- **Cryptographic Primitives**:
    - Key generation
    - BLS signature generation and verification
    - Hash-to-curve functionality
- **Compatibility**: Designed to be compatible with Ethereum's precompiled
  contracts for BN254 operations and [Warlock](https://warlock.xyz/)'s
  [SolBLS](https://github.com/warlock-labs/solbls) library.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sylow = "0.1.0"
```

## Usage

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
                }
                Err(e) => println!("Verification error: {:?}", e),
            }
        }
        Err(e) => println!("Signing error: {:?}", e),
    }
}
```

For more examples, please see [the examples directory](https://github.com/warlock-labs/sylow/tree/main/examples).

## Core Concepts

- **Finite fields**: The foundation of the library, providing arithmetic operations in prime fields and their
  extensions.
- **Elliptic Curve Groups**: Implementations of the 𝔾₁, 𝔾₂, and 𝔾ₜ groups on the BN254 curve, supporting both affine and
  projective coordinates.
- **Pairing**: Efficient implementation of the optimal ate pairing, crucial for many cryptographic protocols.
- **alt-bn128 (BN254) Curve**: A pairing-friendly elliptic curve widely used in zkSNARKs and supported by Ethereum
  precompiles.

## Advanced Features

- **Customizable Hashing**: Supports various hash functions through the `Expander` trait, such as the XMD and XOF
  algorithms on any hasher from [sha3](https://github.com/RustCrypto/hashes/tree/master/sha3).
- **Optimized Arithmetic**: Utilizes Montgomery form for efficient modular arithmetic.
- **Constant-time Operations**: Implements algorithms resistant to timing attacks.
- **Batch Verification**: Verify multiple signatures in a single operation for improved performance.

## Performance

Sylow is designed with performance in mind, leveraging optimized algorithms for j-invariant zero curves, the optimal ate
pairing for efficient signature verification, as well as multiprecision Montgomery arithmetic.

## Security

Sylow is designed in compliance with the recommendations set forth by Cloudflare
in [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380), especially regarding hashing an arbitrary byte array to an
element of the curve. We provide multiple secure implementations of the `hash_to_field` standard and implement the
Shallue-van de Woestijne encoding for elliptic curve points.

The multiprecision arithmetic operations are implemented in constant time, ensuring resistance to side-channel attacks.
Constant-time operations are used whenever possible, and there are currently no variable-time functions used in Sylow.

If you discover any security issues, please report them to [team@warlock.xyz](mailto:team@warlock.xyz).

## Documentation

For detailed API documentation, please refer to [docs.rs/sylow](https://docs.rs/sylow).

## Contributing

We welcome contributions to Sylow! Whether it's bug reports, feature requests, or code contributions, please feel free
to engage with the project by submitting issues, feature requests, or pull requests on
the [GitHub repository](https://github.com/warlock-labs/sylow). We highly recommend reading
our [Devguide](sylow_devguide.pdf) before
contributing to get the required background knowledge.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

This project is maintained by:

- [@trbritt](https://github.com/trbritt) - [tristan@warlock.xyz](mailto:tristan@warlock.xyz)
- [@0xAlcibiades](https://github.com/0xAlcibiades) - [alcibiades@warlock.xyz](mailto:alcibiades@warlock.xyz)
- [@merolish](https://github.com/merolish) - [michael@warlock.xyz](mailto:michael@warlock.xyz)

Warlock Labs - [https://github.com/warlock-labs](https://github.com/warlock-labs)

Project Link: [https://github.com/warlock-labs/sylow](https://github.com/warlock-labs/sylow)