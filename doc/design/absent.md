# What is absent

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## What is absent

**File systems.** None registers (`IoRegisterFileSystem` is absent):
RAW is all there is to mount. RAW enforces no share access between
opens of a volume, and its answers to information queries and
file-system control requests stop the system by name.

No opportunistic locks (a file system's request for one stops the
system by name: `doc/design/fsrtl.md`). No kernel stack segment larger than a thread's stack, and none at
`DISPATCH_LEVEL` (see [Threads](threads.md), stack expansion). No
user-mode APC is delivered (one can be queued; an alertable wait
does not end for it), no sleep states, device power-down ([Power](power.md)), processes
other than System, user-mode code, ALPC ports, I/O completion ports,
priority boosts or registry write-back; the clock ticks at a fixed
rate; NK enforces no security descriptor on its own opens. Microsoft
publishes no arm64 binaries NK may use, so its own drivers run on x86-64
alone. NK has run on no physical machine. NK applies no errata:
it has no errata database (Windows' comes from `errata.inf`, which NK
does not read), and every rule a driver asks the errata manager about
is reported as defined and not applying, where Windows evaluates the
rules of that file; so the workarounds for the hardware it lists are
not made.

**Plug and Play** (the section of that name says what NK does). No
device installation: a driver-database record is applied when a device
is first seen. No arbiters or translators of bus drivers are asked: NK
assigns resources itself. No removal on request, eject, stop or
rebalance, and so none of the notifications that go with them. A filter driver
that is registered for a device or its class and has no image among
the boot files is left out of the stack, where Windows fails the
device: the reference machine registers `EhStorClass` (a KMDF driver
outside the corpus) for disks, and `volsnap` for volumes, which NK's
volume overlay leaves out of the class. `IoCreateArcName` names no disk: the
loader's table of ARC disks is empty (UEFI names none), and the answer
is Windows' for a disk not in it, `STATUS_NOT_SUPPORTED`.
`FsRtlGetVirtualDiskNestingLevel` asks the disk as Windows does; a
disk that answers as a virtual disk stops the system by name.

**Traps.** Where a binary imports a routine in territory NK lacks and
does not reach it on the paths NK runs, the export is `Traps`
(`kernel/export/trap.rs` and `kernel/export/list/trap_*.rs`, which
name them): the import binds, so the
binary loads, and a call stops the system with `BUGCHECK: <name>: NK
does not implement this routine`. One macro makes every such routine,
so none can return. The ledger lists them in the state `traps`, apart
from `implemented`.

**Services NK does not have.** Where Windows' own routine has an
answer for a service that is absent, off or empty, NK gives that
answer, found in the pinned kernel: no feature configuration
(`kernel/rtl/feature.rs`: every feature unconfigured, change
notifications registered and never made), no product policy
(`kernel/ex/license.rs`: every licence value unknown, each name asked
for logged), no shim engine (`kernel/ex/shim.rs`: registration fails as
when Windows' engine is not running), no errata rules
(`kernel/ex/em.rs`: Windows reads the errata manager's database from
an errata file at boot; NK reads none. `pci.sys` does not load unless
it registers as a provider and every rule it asks about is answered,
so NK's database takes its entry types and callbacks from the
providers that register them, checked as Windows checks a registration
whose GUIDs it knows, and answers every rule as Windows answers one
whose conditions do not hold: `STATUS_SUCCESS`, the state false. Each
rule asked about is logged once. Nothing calls a provider's
callbacks), no
driver verifier (`kernel/ex/absent.rs`: nothing is verified, a failure
reported to it goes nowhere), no headless terminal (the same file:
it cannot be enabled, questions are answered with zeros, output
succeeds unseen), no secure kernel (`kernel/ex/vsl.rs`), no
notification states (`kernel/ex/wnf.rs`: a WNF state name is unknown,
`STATUS_OBJECT_NAME_NOT_FOUND`, as Windows answers for a name that has
no instance and that its registry does not list; a name NK's registry
does list stops the system, since Windows would have a state for it),
no paging
file, and a hypervisor only as far as the processor's CPUID names one
(`HviIsAnyHypervisorPresent`, `HviGetHypervisorFeatures`: arm64 says
none). A routine with many sub-functions
answers those a binary reaches and stops the system naming any other
(`kernel/po/mod.rs`, `ZwPowerInformation`). There is no sleep study:
the request for its helper's table of routines fails, where Windows
always has the helper, and `pci.sys` then reports nothing to it.

| Territory | Imported by | Why |
| --- | --- | --- |
| ALPC ports (`ZwAlpc*`) | `msrpc.sys` | `msrpc.sys` is a library, loaded for what it exports; its `DllInitialize` calls none of these, which serve the RPC calls made through it |
| I/O completion ports | `msrpc.sys` | on which `msrpc.sys` waits for its ALPC messages |
| What the storage stack, the volume drivers, the FAT file system and the security drivers import and NK lacks (`kernel/export/list/trap_*.rs`, a list per area) | `acpi.sys`, `pci.sys`, `pshed.dll`, `storport.sys`, `classpnp.sys`, `disk.sys`, `partmgr.sys`, `volmgr.sys`, `volume.sys`, `mountmgr.sys`, `fastfat.sys`, `ksecdd.sys`, `cng.sys` | the lists drive the work: a boot that reaches one names it, and the commit that implements a routine takes its name off the list. An imported variable has no trap: it is absent until it is real |

The `*-neg-trap` scenarios call one through the address its name
resolves to and require the stop that names it.
