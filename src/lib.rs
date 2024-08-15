#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// #![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    // missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2021_compatibility,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

mod fields;
mod groups;
mod hasher;
mod pairing;
mod svdw;
