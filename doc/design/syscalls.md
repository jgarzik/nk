# System calls

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Service table

NK serves the 471 NT system services (`0..=0x1d6`) of Windows 10 19045.2006
x86-64. The committed table in `kernel/svc/services.tsv` records each
service's number, canonical `Nt*` name, 64-bit stack-argument count (matching
`KiArgumentTable[i] / 4`), and whether `ntdll.dll` exports a `syscall` stub
for it (`NtQuerySystemTime`, `#0x5a`, reads `KUSER_SHARED_DATA` directly in
user mode).

- `kernel/build.rs` reads `kernel/svc/services.tsv` at build time and emits
  the `SERVICE_META` table and `nr::Nt*` constants.
- `tools/svctable.py` (tested by `tools/test_svctable.py` in `make test`)
  validates the table and, when `target/fixtures/ntdll.dll` is present,
  re-derives every exported `mov r10, rcx; mov eax, N` stub and requires an
  exact match.
- `kernel/svc/mod.rs` registers every implemented service once via
  `register_services!`, verifying at compile time that its Rust parameter
  count matches `services.tsv`'s stack-argument count.

## `Nt*` vs `Zw*` and `PreviousMode`

Each thread records its caller mode in `KTHREAD.PreviousMode` (offset
`0x232`, PDB-checked), read by `ExGetPreviousMode`
([PreviousMode](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode),
[Nt and Zw](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)):

- The `Nt*` routine is the single implementation. It honours the current
  thread's `PreviousMode` (copying it to `IRP.RequestorMode`, checking
  handles/access and capturing pointers when `UserMode`).
- The `Zw*` export is a generated thunk (`kernel/svc/mod.rs`, `svc::zw`)
  that saves `KTHREAD.PreviousMode`, sets it to `KernelMode`, calls `Nt*`,
  and restores the prior value on return.

## Absent services and information classes

- An index past `SERVICE_COUNT` (`>= 471`) returns
  `STATUS_INVALID_SYSTEM_SERVICE` (`0xC000001C`).
- An unimplemented service inside `0..SERVICE_COUNT` stops the system naming
  the service (`BUGCHECK: NtXxx: NK does not implement this service`).
- An unimplemented information class that Windows 10 19045.2006 defines
  (e.g. `NtQuerySystemInformation` classes `< MaxSystemInfoClass`) stops the
  system naming the service and class; only classes Windows itself rejects
  return `STATUS_INVALID_INFO_CLASS`.
