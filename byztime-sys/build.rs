use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    if let Some(lib_dir) = env::var_os("BYZTIME_LIB_DIR") {
        let lib_dir = Path::new(&lib_dir);
        if lib_dir.join("libbyztime.a").exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-lib=static=byztime");
            return;
        } else {
            println!("cargo:warning={}/libbyztime.a not found, attempting to fall back to in-tree build of libbyztime", lib_dir.display());
        }
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir_arg = format!("outdir={}", out_dir);
    Command::new("make")
        .args(&[out_dir_arg])
        .current_dir(&Path::new("./libbyztime"))
        .status()
        .unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=byztime");
}
