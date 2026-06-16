use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=TitanEngine.h");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root_dir = PathBuf::from(&manifest_dir).parent().unwrap().parent().unwrap().to_path_buf();
    
    // Link search path
    println!("cargo:rustc-link-search=native={}/deps_titan/prebuilt", root_dir.display());
    
    let target = env::var("TARGET").unwrap();
    if target.contains("x86_64") {
        println!("cargo:rustc-link-lib=dylib=TitanEngine");
    } else {
        println!("cargo:rustc-link-lib=dylib=TitanEngine");
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-xc++")
        .allowlist_file(".*TitanEngine\\.h")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
