//! Link `nkt` as a Windows native (`/subsystem:native`) x86-64 PE executable
//! whose entry point is `NtProcessStartup`.

fn main() {
    println!("cargo:rustc-link-arg-bins=/entry:NtProcessStartup");
    println!("cargo:rustc-link-arg-bins=/subsystem:native");
}
