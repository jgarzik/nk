# Development setup

NK is developed on Ubuntu LTS on x86-64. Any Linux with QEMU, UEFI
firmware images and a stable Rust toolchain should work; only the firmware
paths in `tools/boot_test.py` are distribution-specific.

## Packages

```sh
sudo apt-get install make qemu-system-x86 qemu-system-arm \
    ovmf qemu-efi-aarch64 mtools python3
```

| Package | Why |
| --- | --- |
| `qemu-system-x86`, `qemu-system-arm` | boot tests run under QEMU |
| `ovmf`, `qemu-efi-aarch64` | UEFI firmware for the two architectures |
| `mtools` | builds the FAT boot image without root privileges |
| `python3` | the scripts in `tools/` (3.11 or newer) |

No C compiler or cross toolchain is needed: the loader and kernel are
linked by the linker that ships with Rust.

## Rust

Install [rustup](https://rustup.rs). `rust-toolchain.toml` names the
stable channel, the `rustfmt` and `clippy` components, and the two UEFI
targets; rustup fetches whatever is missing the first time you build in
this directory. NK uses no nightly features.

## Everyday commands

```sh
make test       # host unit tests
make check      # boot x86-64 under QEMU and run the kernel self-tests
make check-arm  # the same for arm64 (emulated, a little slower)
make run        # boot with the serial console attached (Ctrl-A X quits)
make gate       # everything a commit must pass
make dist       # release boot images in target/dist/
make clean      # remove target/
```

All build and test output goes under `target/`, including downloaded test
drivers (`target/fixtures/`) and QEMU logs (`target/qemu/`).

x86-64 boot tests use KVM when `/dev/kvm` is usable and fall back to
emulation otherwise; `NO_KVM=1` forces emulation.

## When a boot test fails

- `target/qemu/serial-<arch>.log` is the full serial console.
- A line starting `BUGCHECK:` is a fatal kernel error with a register
  dump. Addresses from `0xFFFFF80000000000` are in the kernel image; the
  driver images are mapped from `0xFFFFF88000000000`.
- `make run` boots the same image interactively.
- QEMU's own tracing (`-d int,cpu_reset`) can be added in
  `tools/boot_test.py` when the kernel dies before it can print.

## Layout of a change

Hardware-independent logic goes in a `lib/` crate with unit tests; the
kernel binary holds the glue and the `unsafe`. See `CONTRIBUTING.md` for
what a change must include.
