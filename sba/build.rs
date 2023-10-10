use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/lib.c");
    println!("cargo:rerun-if-changed=src/lib.h");

    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let outfile = outdir.join("bindings.rs");

    cc::Build::new().file("./src/lib.c").compile("sba");

    let bindings = bindgen::Builder::default()
        .clang_args(["-pthread", "-lrt"])
        .header("./src/lib.h")
        .derive_default(true)
        .generate()
        .expect("failed to generate bindings");

    bindings.write_to_file(&outfile).unwrap();
}
