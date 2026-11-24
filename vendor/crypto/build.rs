use std::{env, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=include");
    println!("cargo:rerun-if-changed=wrapper.hpp");
    let bindings = bindgen::Builder::default()
        .header(root.join("wrapper.hpp").to_string_lossy())
        .clang_args(["-x", "c++", "-std=c++17"])
        .allowlist_file(".*[\\\\/]SharedLibFuncs[\\\\/].*")
        .allowlist_type("mchar")
        .opaque_type("std::.*")
        .layout_tests(true)
        .derive_default(true)
        .generate_comments(true)
        .dynamic_library_name("CryptoPlugin")
        .dynamic_link_require_all(false)
        .wrap_unsafe_ops(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Cannot generate crypto plugin bindings; install libclang and a C++17 toolchain (see README)");
    bindings
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("Cannot write bindings");
}
