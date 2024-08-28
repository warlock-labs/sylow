use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let mut protobuf_out = PathBuf::new();
    protobuf_out.push(&std::env::var("OUT_DIR").unwrap());
    protobuf_out.push(&"protobuf");
    std::fs::create_dir(&protobuf_out).ok();

    prost_build::Config::new()
        .out_dir(&protobuf_out)
        .default_package_filename("mod")
        .compile_protos(&["proto/fp.proto", "proto/fp2.proto"], &["proto/"])?;
    Ok(())
}
