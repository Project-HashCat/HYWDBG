use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=TitanEngine.h");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root_dir = PathBuf::from(&manifest_dir).parent().unwrap().parent().unwrap().to_path_buf();
    
    // We do NOT link against the .lib file anymore!
    // Instead we use bindgen's dynamic library feature to load TitanEngine.dll at runtime.

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-xc++")
        .dynamic_library_name("TitanEngine")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
