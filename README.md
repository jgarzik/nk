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

NK boots through UEFI under QEMU on x86-64 and arm64, loads unmodified
Windows driver binaries and runs real I/O requests through them:

- Microsoft's inbox `null.sys` from Windows 10 (x86-64).
- Microsoft's WDM IOCTL sample `sioctl.sys`, built with the WDK (both
  architectures): buffered and direct I/O, unload, 100 load/unload cycles
  without a leak.

That is two software drivers, not general driver compatibility. There are
no threads, no interrupts, no SEH and no user mode yet, and results have
not been compared with a run on real Windows. `doc/ROADMAP.md` lists what
is open, `ledger/` what each driver imports and how NK answers it, and
`doc/handoff.md` is the original brief.

## Build and test

```sh
make gate     # everything a commit must pass
make help     # the other targets
```

Setup is in `DEVELOPMENT.md`. Design decisions are in `doc/DESIGN.md`.

## License

MIT. Windows driver binaries used as test fixtures are not part of this
repository: tests fetch them by URL and verify them by SHA-256.
