use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    
    // We only need bindgen when building on Windows or doing cross-compilation with a wrapper,
    // but in CI it's fully supported.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // We assume the DLL/Lib is available where the user put it.
    // The user said "编译好的dll我放那里了". We'll just link it.
    // We expect the library to be named `TitanEngine.lib` or `TitanEngine64.lib`.
    // We'll instruct cargo to look in the workspace root or deps_titan/TitanEngine-2025.08.18/TitanEngine
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root_dir = PathBuf::from(&manifest_dir).parent().unwrap().parent().unwrap().to_path_buf();
    
    // Link search path
    println!("cargo:rustc-link-search=native={}", root_dir.display());
    println!("cargo:rustc-link-search=native={}/deps_titan/TitanEngine-2025.08.18/TitanEngine", root_dir.display());
    println!("cargo:rustc-link-search=native={}/deps_titan/TitanEngine-2025.08.18/TitanEngine/x64/Release", root_dir.display());
    
    // In 64-bit builds, it might be called TitanEngine64
    // We try to link TitanEngine or TitanEngine_x64 depending on target
    let target = env::var("TARGET").unwrap();
    if target.contains("x86_64") {
        println!("cargo:rustc-link-lib=dylib=TitanEngine"); // Or TitanEngine64 if they renamed it
    } else {
        println!("cargo:rustc-link-lib=dylib=TitanEngine");
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        // .parse_callbacks(Box::new(bindgen::CargoCallbacks)) // bindgen 0.69 style is different or needs extra features, omit for simplicity
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
