use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    );
    let default_libamt_dir = manifest_dir.join("../../libamt");
    let libamt_dir = std::env::var("LIBAMT_DIR")
        .map(PathBuf::from)
        .unwrap_or(default_libamt_dir);

    println!("cargo:rustc-link-search=native={}", libamt_dir.display());
    println!("cargo:rustc-link-lib=static=amt");
    println!(
        "cargo:rerun-if-changed={}",
        libamt_dir.join("libamt.a").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        libamt_dir.join("amt.h").display()
    );
    println!("cargo:rerun-if-env-changed=LIBAMT_DIR");
}
