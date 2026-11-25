# Development setup

Development host: Ubuntu LTS, x86-64.

## Packages

```sh
sudo apt-get install build-essential qemu-system-x86 qemu-system-arm \
    ovmf qemu-efi-aarch64 mtools lld python3
```

- `qemu-system-*`, `ovmf`, `qemu-efi-aarch64`: boot tests run under QEMU
  with UEFI firmware on both architectures.
- `mtools`: builds the EFI system partition image without root.

## Rust

Install [rustup](https://rustup.rs). `rust-toolchain.toml` selects the
stable channel and the two UEFI targets; rustup installs them on first use.
NK does not use nightly features.

## Everyday commands

```sh
make test     # host unit tests
make gate     # full commit gate
make clean    # remove target/
```

All build and test output goes under `target/`.
