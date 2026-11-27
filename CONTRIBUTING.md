# Contributing

Small, well-tested changes that follow `doc/ROADMAP.md` are the easiest
to accept; for anything larger, open an issue first. Setting up:
`DEVELOPMENT.md`.

## Provenance

NK implements a Windows-compatible driver interface without Windows code.

- **Allowed:** Microsoft's published documentation, headers and driver
  samples, public symbols, and the observed behaviour of binaries you are
  licensed to run.
- **Not allowed:** anything derived from leaked Windows source or the
  Windows Research Kernel; anything translated or adapted from ReactOS,
  Wine or other GPL-licensed code. Reading about a design is fine;
  porting its code is not.
- **No Windows binaries in the tree.** Test drivers are referenced by URL
  and SHA-256 in `fixtures/manifest.toml`.

If unsure whether something qualifies, ask before writing it.

## What a change must do

- **Pass the gates.** `make gate-fast` prints `GATE-FAST-OK` for every
  commit on its own; `make gate` prints `GATE-OK` for the merged result
  (`doc/TESTING.md`).
- **Come with proof.** A Microsoft binary doing its work in a boot
  scenario is the proof of a routine it calls. Algorithmic code gets a
  host unit test in its `lib/` crate; a structure a binary sees gets a
  layout check; a kernel behaviour no Microsoft binary reaches gets a
  boot test (`NK-TEST` line). A bug fix starts with a test that
  reproduces the bug (`doc/TESTING.md`, What gets a test).
- **Stay honest at the driver boundary.** No export reports success for
  work it did not do. An incomplete routine is `Partial` or `Traps` in
  its list under `kernel/export/list/`, with the gap in its doc comment.
- **Be driven by a real driver.** An export is added because a binary in
  the pinned corpus or a pinned fixture imports it.
- **Stay portable.** CPU-specific code lives in `kernel/arch/`; pure
  logic in `lib/`. arm64 is paused until x86-64 reaches `cmd.exe`: it
  must compile (`make clippy-arm`, part of `make gate`), and is booted
  only by `make gate-full`.
- **Document as it goes,** in the same commit. Record NK's decisions;
  link to Microsoft's documentation rather than restating it. Docs state
  the present, not the history.

Conventions: `doc/UNSAFE.md`, `doc/LOCKING.md`, `doc/DESIGN.md` (and the part documents in `doc/design/`).
Driver-visible structures and routines keep their Windows names.

## Commits

Subject: `area: summary`, lower case, naming the code and the functional
change, for example
`io: complete requests through attached completion routines`. The body
says what changed, why, and which test covers it. Git history is the
changelog; there is no changelog file.
