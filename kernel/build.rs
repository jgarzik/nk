//! Link settings for the kernel image.
//!
//! The UEFI targets default to an EFI application whose entry point is
//! `efi_main`. The kernel is a PE image started by nkload, not by firmware:
//! name its real entry point and mark it a native (kernel-mode) image.

fn main() {
    println!("cargo:rustc-link-arg-bins=/entry:nk_entry");
    println!("cargo:rustc-link-arg-bins=/subsystem:native");
}
