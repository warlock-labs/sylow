# sylow

[![License](https://img.shields.io/crates/l/sylow)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/sylow)](https://crates.io/crates/sylow)
[![Docs](https://img.shields.io/crates/v/sylow?color=blue&label=docs)](https://docs.rs/sylow/)
![CI](https://github.com/warlock-labs/sylow/actions/workflows/CI.yml/badge.svg)

sylow is a Rust library implementing the BLS (Boneh-Lynn-Shacham) signature scheme using the alt-bn128 (BN254) elliptic curve. It provides threshold signing capabilities and associated utilities, initially developed for use in the Warlock Chaos product.

## Features

- Implementation of BLS signatures on the alt-bn128 (BN254) curve
- Support for threshold signatures
- Efficient pairing operations leveraging the alt-bn128 curve's properties
- Utilities for key generation, signing, and verification
- Compatibility with Ethereum's precompiled contracts for alt-bn128 operations

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
sylow = "0.0.1"
```

Here's a basic example of generating a key pair, signing a message, and verifying the signature:

```rust
use sylow::{KeyPair, sign, verify};

fn main() {
    let key_pair = KeyPair::generate();
    let message = b"Hello, World!";
    
    if let Ok(signature) = sign(&key_pair.secret_key, message){
        if let Ok(verify) = verify(&key_pair.public_key, message, &signature){
            assert!(verify, "Signature verification failed");
        }
    }
}
```

For more examples and usage details, see the [API documentation](https://docs.rs/sylow).

## Core Concepts

- **BLS Signatures**: A signature scheme allowing for signature aggregation and threshold signing.
- **alt-bn128 (BN254) Curve**: An elliptic curve with efficient pairing operations, widely used in zkSNARKs and supported by Ethereum precompiles.
- **Threshold Signatures**: A cryptographic primitive allowing a subset of parties to collaboratively sign messages.

## Performance

The alt-bn128 curve is chosen for its efficiency and widespread support, particularly in Ethereum and other EVM-compatible blockchains. The library aims to provide optimal performance for BLS operations on this curve.

## Roadmap

The following features and improvements are planned for future releases:

- [ ] Basic BLS signature implementation
- [ ] Key generation utilities
- [ ] Signature aggregation
- [ ] Threshold signature scheme
- [ ] Optimizations for common operations
- [ ] Extended test suite and benchmarks
- [ ] Support for serialization formats used in blockchain contexts

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests on the [GitHub repository](https://github.com/warlock-labs/sylow).

## License

This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/).

## Contact

Warlock Labs - [https://github.com/warlock-labs](https://github.com/warlock-labs)

Project Link: [https://github.com/warlock-labs/sylow](https://github.com/warlock-labs/sylow)