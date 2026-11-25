# Contributing

NK is at its first milestone and the design is still moving. Small,
well-tested changes that follow the roadmap are the easiest to accept;
for anything larger, open an issue first.

## Provenance: where code may come from

NK implements a Windows-compatible driver interface without Windows code.

- **Allowed sources:** Microsoft's published documentation and headers
  (the WDK, Microsoft Learn, the PE format specification), public symbol
  information, Microsoft's published driver samples, and the observed
  behaviour of binaries you are licensed to run.
- **Not allowed:** anything derived from leaked Windows source code or the
  Windows Research Kernel, and anything translated or adapted from
  GPL-licensed implementations such as ReactOS or Wine's kernel-side code.
  Reading about a design is fine; porting its code is not.
- **No Windows binaries in the tree.** Test drivers are referenced by URL
  and SHA-256 in `fixtures/manifest.toml`. Third-party code with a
  compatible licence must keep its attribution.

If you are unsure whether something qualifies, ask before writing it.

## What a change must do

- **Pass the gate.** `make gate` prints `GATE-OK`. Every commit passes it
  on its own, so history can be bisected.
- **Come with tests.** A pure function gets a host unit test in its `lib/`
  crate. A kernel behaviour gets a boot self-test that prints an
  `NK-TEST` line. A bug fix starts with a test that reproduces the bug.
- **Stay honest at the driver boundary.** No export may report success for
  work it did not do. If a routine is incomplete, mark its state in
  `kernel/export/mod.rs` as `Partial` or `Traps` and say what is missing
  in its doc comment.
- **Be driven by a real driver.** New exports are added because a driver
  in the fixture set imports them, not to grow the list.
- **Build for both architectures.** x86-64 and arm64 are equals;
  CPU-specific code lives under `kernel/arch/`.
- **Document as it goes.** Update the relevant file in `doc/` in the same
  commit. Record NK's decisions; link to Microsoft's documentation rather
  than restating it.

Code conventions: `doc/UNSAFE.md` for `unsafe`, and `doc/DESIGN.md` for
how the pieces fit. Driver-visible structures and routines keep their
Windows names so they can be searched for.

## Commits

Subject lines are `area: summary` in lower case, for example
`io: complete requests through attached completion routines`. The body
says what changed and why, and which test covers it. There is no
changelog file: the git history is the changelog.

## Setting up

See `DEVELOPMENT.md`.
