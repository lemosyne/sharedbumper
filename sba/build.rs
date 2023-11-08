use std::{env, path::PathBuf};

const TARGET_FILES: &[&str] = &["lib.c", "lib.h"];

fn main() {
    for file in TARGET_FILES {
        println!("cargo:rerun-if-changed=src/{file}");
    }

    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let outfile = outdir.join("bindings.rs");

    cc::Build::new().file("./src/lib.c").compile("sba");

    let bindings = bindgen::Builder::default()
        .clang_args(["-pthread", "-lrt", "-O3", "-g"])
        .header("./src/lib.h")
        .derive_default(true)
        .generate()
        .expect("failed to generate bindings");

    bindings.write_to_file(&outfile).unwrap();
}
