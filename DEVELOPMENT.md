# Development setup

NK is developed on Ubuntu LTS on x86-64. Any Linux with QEMU, UEFI
firmware images and a stable Rust toolchain should work; only the firmware
paths in `tools/boot_test.py` and `tools/oracle.py` are
distribution-specific.

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

`make oracle`, which replays the oracle scripts on real Windows, also
needs KVM, `qemu-utils` (for `qemu-img`) and `xorriso`. Nothing else
uses them; see `doc/TESTING.md`.

## Rust

Install [rustup](https://rustup.rs). `rust-toolchain.toml` names the
stable channel, the `rustfmt` and `clippy` components, and the two UEFI
targets; rustup fetches whatever is missing the first time you build in
this directory.

## Everyday commands

```sh
make test       # host unit tests
make check      # boot x86-64 under QEMU and run the kernel self-tests
make check-arm  # the same for arm64 (emulated, slower)
make run        # boot with the serial console attached (Ctrl-A X quits)
make gate-fast  # what every commit must pass; prints GATE-FAST-OK
make gate       # what the merged tip must pass; prints GATE-OK
make gate-full  # both architectures, every scenario; prints GATE-FULL-OK
make help       # the other targets
make dist       # release boot images in target/dist/
make clean      # remove target/
```

All build and test output goes under `target/`, including downloaded test
drivers (`target/fixtures/`) and QEMU logs (`target/qemu/`).

x86-64 boot tests use KVM when `/dev/kvm` is usable and fall back to
emulation otherwise; `NO_KVM=1` forces emulation.

## When a boot test fails

- The failing scenario's directory, `target/qemu/<scenario>/`, is kept
  and its path printed: `serial.log` is the full serial console, and after
  a hang `hang-registers.txt` has every CPU's registers.
  `target/qemu/serial-<arch>.log` is the last main boot of each
  architecture.
- `tools/boot_test.py <scenario>` reruns one scenario; `KEEP=1` keeps its
  directory even when it passes.
- A line starting `BUGCHECK:` is a fatal kernel error with a register
  dump. Addresses from `0xFFFFF80000000000` are in the kernel image;
  driver images and kernel stacks are mapped from `0xFFFFF88000000000`
  (`doc/DESIGN.md`, Address space).
- `make run` boots the same image interactively.
- QEMU's own tracing (`-d int,cpu_reset`) can be added in
  `tools/boot_test.py` when the kernel dies before it can print.

## Releases

Tagged `vX.Y.Z`; the version is in the workspace `Cargo.toml` and the
kernel prints it at boot. A release is the tagged source plus one boot
image per architecture from `make dist`, holding only NK's loader and
kernel: booted, they run the kernel's self-tests and skip the driver
tests.
