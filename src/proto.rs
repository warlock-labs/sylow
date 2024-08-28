#[cfg(feature = "serialize")]
pub mod fp {
    include!(concat!(env!("OUT_DIR"), "/protobuf/fp.rs"));
}
#[cfg(feature = "serialize")]
pub mod fp2 {
    include!(concat!(env!("OUT_DIR"), "/protobuf/fp2.rs"));
}
