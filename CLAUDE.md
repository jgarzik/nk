nk: stable-Rust (no nightly, never pin a version) NT-compatible kernel,
x86-64 + arm64. Crates have no `src/` dirs. Code that touches a CPU or
device goes in `kernel/arch/` or `kernel/hal/`; pure logic goes in `lib/`
where the host can unit-test it.

## Mission
- Golden rule: an unmodified Windows 10 (2004-22H2, NT 10.0.19041-19045)
  kernel driver cannot tell NK from Windows. The driver ABI is binding:
  exports, calling conventions, structure layouts, IRQL and lifetime
  rules. What no binary can observe is ours to design.
- NK is `ntoskrnl.exe` + `hal.dll` + a loader, nothing else. Bus, ACPI,
  storage, file-system, framework and window-system drivers are
  Microsoft's binaries; so is all of user mode. Destination: Microsoft's
  WinPE at a `cmd.exe` prompt (`doc/ROADMAP.md`).
- Both arches are first class: every commit builds both.
- Scope follows the import tables of real binaries (`ledger/`), not the
  size of the Windows export list.
- NK code is written fresh: read hk, ReactOS and Wine; copy none of them.

## Build / verify
- Makefile targets only. Done = `make gate` prints GATE-OK.
- Bisectable: every commit passes the gate alone. `main` is protected:
  commit on a branch (`updates`); the maintainer pushes and merges. Never
  amend. Never commit after a gate whose exit status was hidden by a pipe.
- Tests grow with the kernel: a pure function gets a host unit test, a
  kernel behaviour gets a boot test line (`NK-TEST name:OK`).
- Tests clean up after themselves; all output lives under `target/`.

## Rules
- No fake success. A missing import rejects the driver load and names
  the symbol. An export that cannot do its job fails per its contract or
  bugchecks; it never returns success without doing the work.
- Structs a binary can see, documented or private, live in `lib/ntabi`
  as `#[repr(C)]` with const size/offset asserts. Never hand a driver a larger private struct, and
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
- Releases: version in the workspace `Cargo.toml`, tag `vX.Y.Z`, images
  from `make dist` (no Windows binaries in them).

- Locks: `doc/LOCKING.md` states the ranks and rules; a new or changed
  lock updates it in the same commit.

Design: `doc/DESIGN.md`. Phases: `doc/ROADMAP.md`. Tests: `doc/TESTING.md`.
