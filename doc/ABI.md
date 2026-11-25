# ABI notes

What was measured about the compiler targets, and what the kernel relies
on. Layout verification of individual structures is tracked in the
ledger, not here.

## Compiler targets (measured on stable rustc 1.100.0)

| Question | x86_64-unknown-uefi | aarch64-unknown-uefi |
| --- | --- | --- |
| Integer argument registers for `extern "C"` | rcx, rdx, r8, r9, then stack above 32 bytes of shadow space: the Microsoft x64 convention | x0-x7 |
| Platform register | n/a | x18 never appears in generated code |
| Defining C-variadic functions (`...`) | compiles; `VaList::next_arg` | compiles |
| Floating point | soft-float: `f64` arguments travel in integer registers and arithmetic calls `__muldf3` | hardware (NEON) |

Consequences:

- Exported functions are plain `extern "C"` and are Windows-ABI correct
  for integer and pointer arguments on both targets.
- **x86-64 floating-point arguments are not Windows-ABI correct.** The
  target does not use SSE registers. No kernel export in the MVP takes a
  float, and the kernel itself uses none (`clippy::float_arithmetic`
  warns). An export that needs one must go through an assembly thunk.
- Because NK's own code never touches XMM registers on x86-64, a driver's
  SSE state survives calls into the kernel without save/restore. The
  kernel still has to keep SSE enabled, since drivers use it.
- x18 holds the processor control region on arm64 Windows; the target
  leaves it alone, so the kernel can set it once per CPU.
- `DbgPrint` and friends can be written in Rust.

How to re-measure: compile a small `#![no_std]` library for each target
with `rustc --emit asm` and read the argument registers.

## Not yet verified

- Structure layouts against WDK headers: pending the ABI probe in the
  fixtures repository.
- Behaviour against a real Windows 10 installation: no reference VM yet.
