nk: stable-Rust (no nightly, never pin a version) NT-compatible kernel,
x86-64 + arm64. Crates have no `src/` dirs. Code that touches a CPU or
device goes in `kernel/arch/` or `kernel/hal/`; pure logic goes in `lib/`
where the host can unit-test it.

## Mission
- Run unmodified Windows 10 22H2 (NT 10.0.19045) kernel drivers. The
  driver ABI is binding: exports, calling conventions, structure layouts,
  IRQL and lifetime rules. Internals are ours to design.
- Both arches are first class: every commit builds both.
- Scope follows the import tables of real drivers (`ledger/`), not the
  size of the Windows export list. Brief: `doc/handoff.md` (advisory).

## Build / verify
- Makefile targets only. Done = `make gate` prints GATE-OK.
- Bisectable: every commit passes the gate alone. Commit locally; never
  push, never amend.
- Tests grow with the kernel: a pure function gets a host unit test, a
  kernel behaviour gets a boot test line (`NK-TEST name:OK`).
- Tests clean up after themselves; all output lives under `target/`.

## Rules
- No fake success. A missing import rejects the driver load and names
  the symbol. An export that cannot do its job fails per its contract or
  bugchecks; it never returns success without doing the work.
- Driver-visible structs live in `lib/ntabi` as `#[repr(C)]` with const
  size/offset asserts. Never hand a driver a larger private struct, and
  never hold a Rust reference into memory a driver can write.
- Windows binaries are never committed. Fixtures are fetched by URL and
  pinned by SHA-256 (`fixtures/manifest.toml`); a missing fixture is a
  SKIP, never a PASS.
- Generic code plus arch callbacks in `kernel/arch/{x86_64,aarch64}/`;
  no scattered `#[cfg(target_arch)]`.
- SMP-safe from the start: per-CPU state behind the PCR, real locks, no
  single-CPU assumptions, even while only the boot CPU runs.
- `unsafe`: `doc/UNSAFE.md`. `// SAFETY:` on every block, `# Safety` on
  every unsafe fn, no `static mut`.
- Document as you go, in the same commit. Record NK's decisions; link to
  Microsoft's documentation instead of restating it.
- No CHANGELOG/NEWS files. No dead or speculative code.

Design: `doc/DESIGN.md`. Phases: `doc/ROADMAP.md`. Tests: `doc/TESTING.md`.
