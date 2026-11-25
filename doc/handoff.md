# NK: Rust NT Kernel — Claude Code Handoff

## 1. Mission

Build a modern, permissively licensed, native Windows NT-compatible kernel in
Rust for AMD64 (x86-64) and AArch64 (ARM64). Windows 10 22H2, NT 10.0 build
19045, is the fixed compatibility target. Pin the exact servicing revision and
architecture of each reference installation.

The project's defining objective is to run existing, unmodified Windows
kernel-mode drivers. The Windows driver ecosystem is a strategic asset: NK
should ultimately be able to operate hardware using existing Windows driver
binaries rather than having to recreate the entire driver ecosystem from
scratch.

NK is not initially a Windows desktop clone, a Linux compatibility layer, or an
NT-inspired hobby OS. It is an independently bootable NT kernel and driver
platform. Userspace, Wine integration, and broader Windows operating system
compatibility can follow.

**Windows defines the external ABI and observable behavior. Rust defines the
implementation, not a new driver contract.**

## 2. Non-negotiable project decisions

- Rust-first kernel, with narrowly scoped C, C++, and assembly permitted when
  required for ABI fidelity, compiler support, or useful permissively licensed
  components. Prefer MIT licensing for NK-owned code.
- AMD64 and AArch64 are first-class architectures. Neither is an optional future
  port. No 32-bit kernels or cross-architecture kernel driver emulation.
- Native execution of unmodified, architecture-matching Windows `.sys` binaries
  is mandatory. Source compatibility alone is insufficient.
- Use Windows 10 22H2 as the behavioral oracle. Do not chase newer Windows
  releases during initial development.
- Preserve conventional NT architectural concepts and subsystem boundaries where
  they help maintain compatibility. Private implementation details may differ
  from Microsoft Windows.
- Favor correctness, ABI fidelity, and observability over performance and
  idiomatic Rust where those objectives conflict. Design for SMP even when the
  first milestone runs on one CPU.
- Develop and test on QEMU x86-64, QEMU AArch64, and a physical Dell OptiPlex
  PC. Prefer UEFI on all three platforms.

## 3. Absolute minimum MVP: NK 0.0.1 — Driver Bootstrap

The smallest meaningful MVP is a bare-metal NT driver execution environment. It
must boot independently of Windows and Linux, load a genuine Windows-format
kernel driver, and perform a real I/O request through that driver.

The release should accomplish the following observable sequence:

1. Boot from an independently bootable image, exit UEFI boot services, and
   establish NK-owned CPU and memory state.
2. Load an architecture-matching PE32+ Windows driver supplied as an in-memory
   boot module; map it, apply relocations, and resolve its imports.
3. Invoke its real entry point with valid NT-compatible arguments and calling
   conventions. The driver creates a device and registers dispatch routines.
4. Open the device through NK's minimal object and I/O infrastructure, submit a
   genuine IRP, observe completion, and validate status, byte count, and output.
5. Close the device, unload drivers that support unloading, and verify correct
   resource ownership and cleanup.
6. Emit deterministic, machine-readable PASS/FAIL results through a diagnostic
   console and halt or exit the test environment.

No Windows kernel binary, Windows runtime, or proprietary bootloader may be
required for NK to boot. A bootloader-provided driver module avoids the need for
a native filesystem or disk driver at this stage.

**Zero userspace system calls and zero userspace processes are acceptable for
this release.** SMP execution may also be deferred, but interfaces and
synchronization design must not depend on permanent single-CPU execution.

A software-driver MVP is a deliberately limited proof of binary
interoperability. It is not proof of general Windows hardware driver
compatibility.

## 4. Define progress by the driver ABI, not system calls

The primary compatibility surface is the NT kernel-mode Device Driver Interface
(DDI). System call counts, Win32 API counts, and lines of code are not useful
MVP release gates.

The driver ABI includes exported functions and variables, calling conventions,
exact public and externally accessed structure layouts, callbacks, object
lifetimes, memory and synchronization semantics, processor state, and inline
operations compiled into drivers from WDK headers.

Create a machine-readable compatibility ledger for both architectures. The
ledger should record the pinned Windows reference, selected driver binaries and
hashes, actual imported symbols and their modules, ABI verification results,
behavioral test results, and driver functional outcomes. Distinguish missing,
stubbed, partial, and verified interfaces. A resolved import is not an
implemented behavior.

Generate the initial implementation backlog from the real PE import tables of
the pinned driver corpus, including any compiler-generated runtime dependencies.
Keep a broader inventory of the reference Windows kernel and HAL exports, but
prioritize the dependencies of actual drivers rather than maximizing export
counts.

### Representative initial ABI surface

The following is a seed list, not a fixed or exhaustive implementation
checklist. The selected binaries and independently measured behavior determine
the actual MVP scope.

- **Executive pool:** `ExAllocatePoolWithTag`, `ExFreePoolWithTag`
- **Device objects:** `IoCreateDevice`, `IoDeleteDevice`
- **Namespace:** `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`
- **IRP lifecycle:** `IoAllocateIrp`, `IoFreeIrp`
- **IRP dispatch:** `IofCallDriver`, `IofCompleteRequest`
- **Runtime:** `RtlInitUnicodeString`, `RtlCompareUnicodeString`
- **Dispatcher:** `KeGetCurrentIrql`, `KeInitializeEvent`, `KeSetEvent`
- **Diagnostics:** `DbgPrint`, `DbgPrintEx`

The initial I/O model should support the synchronous, buffered operations
required by the selected drivers, including create, cleanup, close, read, write,
and device control as applicable. Defer asynchronous completion and cancellation
unless required by the pinned MVP fixtures.

Key ABI structures include `DRIVER_OBJECT`, `DRIVER_EXTENSION`, `DEVICE_OBJECT`,
`FILE_OBJECT`, `IRP`, `IO_STACK_LOCATION`, `IO_STATUS_BLOCK`, `UNICODE_STRING`,
`LIST_ENTRY`, `KEVENT`, and `DISPATCHER_HEADER`. Processor-local structures and
externally accessed fields, including KPCR-related state, must also be correct
where required.

Verify sizes, alignments, field offsets, bitfields, initialization, and
externally observable semantics using independent WDK-compiled probes and
appropriate reference information. Never substitute larger private Rust
structures for driver-allocated ABI objects.

## 5. Reuse strategy and existing source code

Create NK as an independent project, with selectively reused HK infrastructure
and independently validated NT-specific components. Do not compromise HK's Linux
compatibility mission or automatically adopt another project's incompatible NT
abstractions.

- **[HK][hk]:** Allocators, MMU, CPU bring-up, interrupts, diagnostics, SMP
  foundations, QEMU and differential testing infrastructure.
- **[nanokrnl][nano]:** Candidate PE loader, NT executive and runtime
  components, and useful experiments. Import only code that passes independent
  ABI and provenance review.
- **[uefi-rs][uefi] / [EDK II][edk]:** UEFI boot infrastructure and QEMU
  firmware.
- **[windows-drivers-rs][wdk-rs]:** WDK bindings, ABI reference material and
  driver test build tooling.
- **[Goblin][goblin]:** Candidate Rust PE parser; validate freestanding support
  and licensing.
- **[Windows Driver Samples][samples]:** Independent WDK driver fixtures and
  reference behaviors.
- **[Windows DDI documentation][ddi]:** Primary published driver interface
  specifications.
- **[VirtIO Windows drivers][virtio]:** First major real hardware-driver
  compatibility corpus.
- **[Microsoft WDF][wdf]:** Later KMDF/UMDF work; source availability does not
  guarantee a standalone build.
- **[ReactOS][reactos]:** Established NT compatibility work and research
  context; do not transplant GPL implementation into the MIT kernel.

HK and nanokrnl are described as MIT-licensed, but verify exact revisions,
dependency licenses, and source provenance before reuse. Reuse decisions are not
commitments to import whole repositories. No comprehensive source or dependency
audit has yet been performed.

Nanokrnl already demonstrates AMD64 Windows software-driver execution, including
Microsoft `null.sys` according to its published results. It is useful prior art,
not proof of broad Windows hardware-driver compatibility. Earlier source review
identified incompatible ABI choices, including oversized dispatcher objects and
a nonstandard `DbgPrint` signature. Treat these as examples to investigate, not
as assumptions about every future revision. Do not use nanokrnl's private ABI or
its own mutually consistent tests as the specification for NK.

## 6. Critical implementation guardrails

- Preserve exact Windows calling conventions and data layouts. On AMD64, support
  the Microsoft x64 ABI and required GS-based processor state. On ARM64, honor
  the Windows ABI, including reserved `x18` and KPCR conventions. Verify the
  compiler target, not merely the function declaration.
- The kernel itself need not use PE format. A freestanding ELF kernel is a
  reasonable starting point if it preserves foreign ABI requirements. Let the
  agent evaluate target and linker tradeoffs, including eventual unwind support.
- Treat foreign kernel drivers as trusted but memory-unsafe code. Do not
  construct Rust references that assume exclusive access to driver-mutated
  objects. Use carefully reviewed unsafe boundaries and preserve ABI-visible
  mutable state.
- No fake-success stubs, fabricated completion results, or driver-specific
  shortcuts to pass tests. Missing imports must be reported explicitly.
  Unsupported operations must fail according to their contracts; never silently
  no-op a required operation that cannot fail.
- Respect IRQL, ownership, memory permissions, synchronization, and resource
  lifetime contracts. Add debug-time checks and fail loudly when invariants are
  violated.
- Do not confuse Rust panics with Windows SEH. Full kernel-mode SEH can be
  deferred only if the selected proof drivers do not require unsupported
  behavior. Do not claim SEH compatibility prematurely.
- No leaked Windows source or restricted Windows Research Kernel material. Use
  published specifications, licensed sources, and independently observed
  behavior. Do not translate GPL code into an MIT implementation. Preserve
  attribution and dependency licensing.
- Proprietary Windows binaries are external, legally obtained test fixtures, not
  NK distribution dependencies. Do not redistribute them without permission.
  Initial testing should use approved drivers and disposable environments;
  arbitrary driver execution and production trust policy are later concerns.

## 7. Driver corpus and independent testing

The first release requires two driver classes on each supported architecture:

1. **Minimal WDM echo driver:** Independently compiled with genuine Microsoft
   WDK headers and tooling, without NK or nanokrnl headers. It must first work
   on genuine Windows 10. Validate initialization, device creation, synchronous
   buffered IOCTLs with nontrivial payloads, open/close, unload, and cleanup.
2. **Genuine Windows inbox `null.sys`:** Use an unmodified binary from the
   pinned reference installation. Validate read/write results and device
   behavior against Windows. Do not require unload if the reference driver does
   not support it. Verify that the selected binary and its dependency closure
   are suitable on each architecture; if not, document the blocker and obtain
   approval for an equivalent independently developed inbox-driver fixture.

The same driver binary must execute on the corresponding Windows reference and
NK. Record its hash; do not rebuild or patch it to accommodate NK. Compile
separate AMD64 and ARM64 binaries as appropriate. Microsoft SIOCTL is the next
independent sample, not a requirement to implement all buffering modes in 0.0.1.

Follow HK's differential testing philosophy: genuine Windows establishes
expected behavior, not the agent, an alternative kernel, or a test sharing NK's
own ABI declarations. Use independent WDK probes, negative tests, canaries
around ABI allocations, and resource-accounting checks. Compare observable
results rather than incidental pointer addresses or timing.

The Windows AMD64 and ARM64 reference VMs must be legally obtained and
reproducibly configured. Establish availability of a working Windows 10 22H2
ARM64 reference early. If it is unavailable, mark ARM64 differential conformance
blocked rather than silently substituting Windows 11 or claiming parity.

## 8. MVP acceptance gates

All required gates must pass for release 0.0.1. The agent owns the detailed
engineering plan; the following specifies the outcomes.

- **Reproducible build:** Independently bootable AMD64 and ARM64 images produced
  by documented build/test commands.
- **Virtual boot:** Both QEMU architectures boot through UEFI and reach NK-owned
  execution, with reliable diagnostics.
- **Physical boot:** The Dell OptiPlex boots and runs the same AMD64
  software-driver proof suite.
- **ABI verification:** Every driver-visible layout, function signature, and
  calling convention required by the pinned proof corpus independently
  validated.
- **Import resolution:** All required imports resolve to real implementations;
  no fake-success paths.
- **Driver execution:** Both driver classes initialize and execute without
  binary modifications on each target architecture.
- **Functional I/O:** Real IRP dispatch/completion path produces
  reference-equivalent status, byte count and payload or other observable
  result.
- **Lifecycle:** Unloadable echo driver survives 100 load/exercise/unload cycles
  per QEMU architecture with no attributable leaked allocations or references.
- **Negative tests:** Wrong-architecture images and unresolved imports are
  rejected; invalid supported requests fail correctly.
- **Regression gate:** Automated, repeatable test reports cover Windows
  reference results and NK results, including failures and skipped tests.

Track these metrics separately: required imports implemented, ABI layouts and
signatures verified, behavioral tests passed, driver functional tests passed,
and eventually real hardware driver tests passed. Publish denominators and
distinguish skipped or blocked tests from passes.

## 9. Explicitly out of scope for 0.0.1

Userspace processes, native system calls, NTDLL, Win32, GUI, persistent
registry, native filesystems, disk drivers, networking, full PnP/power
management, DMA, KMDF, Storport, NDIS, WDDM, and full SEH. SMP operation is a
subsequent gate. None of these exclusions permits incorrect implementation of
functionality actually required by the chosen proof drivers.

Avoid premature build-out of subsystems just because they exist in Windows.
Deliver the smallest honest vertical slice of the NT driver contract first.

## 10. Roadmap beyond the bootstrap

- **0.0.1 — Bootstrap:** Independently boot and execute real Windows software
  drivers on both architectures.
- **0.0.2 — Executive:** SMP, richer dispatcher and I/O semantics, layered
  driver stacks, cancellation, and independent SIOCTL tests. Add minimal
  userspace where needed for conformance.
- **0.0.3 — Hardware:** Existing unmodified Windows driver performs functional
  I/O against a real QEMU virtual device. Choose the first driver by measured
  dependency complexity, not by device simplicity alone.
- **0.0.4 — Storage:** Use an existing Windows storage driver (e.g. a suitable
  VirtIO Storport miniport) for persistent storage and mount a filesystem on it.
  Subsequently boot the NK system volume through that driver.
- **Later:** NDIS and Windows Ethernet drivers, broader KMDF support,
  INF/package installation, selected Dell physical hardware drivers, and
  eventually Windows application compatibility.

The major strategic proof is real hardware operation through an existing Windows
driver, not merely running a PE binary. The Windows driver ecosystem includes
substantial additional contracts such as KMDF, Storport, NDIS, USB, and WDDM. Do
not imply that implementing `ntoskrnl.exe` exports alone unlocks them all.

## 11. First assignment for Claude Code

Establish the reproducible reference environments and independently compiled
proof corpus. Inventory their actual binary dependencies, determine the minimal
NT ABI closure for each architecture, and assess reusable code from HK and
nanokrnl against that contract. Produce a concise engineering plan and
compatibility ledger, then build toward the 0.0.1 acceptance gates.

Make decisions at the appropriate engineering level. Do not expand the mission,
change the Windows reference, weaken the driver compatibility requirement, or
introduce new mandatory subsystems without explaining the tradeoff. Report
actual measured outcomes, provenance issues, and blockers. The goal is a working
kernel, not a large scaffold or a large count of exported names.

**North star: build a kernel that existing Windows drivers believe is Windows.**

[hk]: https://github.com/jgarzik/hk
[nano]: https://github.com/msuiche/nanokrnl
[uefi]: https://github.com/rust-osdev/uefi-rs
[edk]: https://github.com/tianocore/edk2
[wdk-rs]: https://github.com/microsoft/windows-drivers-rs
[goblin]: https://github.com/m4b/goblin
[samples]: https://github.com/microsoft/Windows-driver-samples
[ddi]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/_kernel/
[virtio]: https://github.com/virtio-win/kvm-guest-drivers-windows
[wdf]: https://github.com/microsoft/Windows-Driver-Frameworks
[reactos]: https://github.com/reactos/reactos

Additional reference material:

- [Microsoft PE
  format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft WDM SIOCTL
  sample](https://github.com/microsoft/Windows-driver-samples/tree/main/general/ioctl/wdm)
- [Windows system call tables](https://github.com/j00ru/windows-syscalls) (later
  userspace ABI work)
