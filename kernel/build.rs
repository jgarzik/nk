//! Link settings for the kernel image.
//!
//! The UEFI targets default to an EFI application whose entry point is
//! `efi_main`. The kernel is a PE image started by nkload, not by firmware:
//! name its real entry point and mark it a native (kernel-mode) image.

fn main() {
    println!("cargo:rustc-link-arg-bins=/entry:nk_entry");
    println!("cargo:rustc-link-arg-bins=/subsystem:native");
    // A link map beside the image (`nkkrnl.map`): `tools/unwind_coverage.py`
    // names the code without unwind entries from it. Build scripts get
    // an output directory somewhere under `build/`, which sits beside
    // the image.
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let image_dir = out
        .ancestors()
        .find(|dir| dir.file_name().is_some_and(|name| name == "build"))
        .and_then(|build| build.parent())
        .expect("OUT_DIR is under build/");
    println!(
        "cargo:rustc-link-arg-bins=/map:{}",
        image_dir.join("nkkrnl.map").display()
    );
}
