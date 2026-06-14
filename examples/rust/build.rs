use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = manifest
        .join("../../zig-out/lib")
        .canonicalize()
        .expect("zig-out/lib not found — run `zig build` from the repo root first");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=signal_ffi");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
}
