# NK

A Windows NT-compatible kernel in Rust for modern multicore 64-bit machines:
x86-64 and arm64.

## Mission

Run existing, unmodified Windows kernel-mode drivers. The compatibility
target is fixed: Windows 10 22H2, NT 10.0 build 19045. Windows defines the
driver ABI and the observable behaviour; Rust defines the implementation.

The contract we set out to prove is binary compatibility with Windows
drivers already in the field: the same `.sys` file that loads on Windows
loads on NK. Compatibility is reached incrementally, one real driver at a
time, and progress is measured by the driver interface (imports resolved,
layouts verified, I/O behaving as on Windows), not by system-call counts.

NK is not a Windows desktop clone and not a Linux compatibility layer. It
boots on its own, with no Windows or Linux component in the boot path.

## Status

Pre-0.0.1. See `doc/ROADMAP.md` for what works and what is next, and
`doc/handoff.md` for the original brief.

## Build and test

```sh
make gate     # everything a commit must pass
make help     # the other targets
```

Setup is in `DEVELOPMENT.md`. Design decisions are in `doc/DESIGN.md`.

## License

MIT. Windows driver binaries used as test fixtures are not part of this
repository: tests fetch them by URL and verify them by SHA-256.
