# Roadmap

The phases from today's NK to a Windows rescue disk: Microsoft's Windows
10 user mode at a `cmd.exe` prompt on a kernel that is entirely NK. This
file fixes the order, its reason, and what proves a phase done; each
phase gets a detailed plan when it starts. What NK is and its principles:
`doc/DESIGN.md`. What runs today: `README.md`.

## Destination

A FAT32 volume holding Microsoft's Windows PE image, applied flat
([Microsoft's "flat boot"](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-install-on-a-hard-drive--flat-boot-or-non-ram)),
booted by `nkload` and NK in place of Microsoft's boot manager, loader,
kernel and HAL. Every other file is Microsoft's and unmodified. It reaches
the `X:\windows\system32>` prompt on QEMU x86-64 and on the Dell OptiPlex,
and on QEMU arm64 once arm64 Windows files can be obtained.

Flat boot is the target because it needs the fewest drivers: no RAM disk,
no WIM filter, no NTFS. Booting an untouched `boot.wim` comes after.

## Measurements

Microsoft's kernel-mode binaries of the pinned build (x86-64), the
drivers and the libraries they import from, are listed in
`fixtures/corpus.toml`. `tools/corpus.py` fetches them and writes down
what each imports; `ledger/x86_64.json` has the counts, per binary, of
names imported from `ntoskrnl.exe` and `hal.dll` and how many NK
provides. What the counts say:

- **The whole corpus needs a little over half of the kernel's named
  exports.**
- **Running Microsoft's frameworks is cheap at the kernel boundary.** KMDF
  and the USB stack each add a couple of dozen names, because the
  Microsoft binaries carry the rest. `storahci.sys` imports nothing from
  the kernel at all, only from `storport.sys`. Writing those layers
  ourselves would cost years and add a second ABI to get wrong.
- **`hal.dll` is a shell.** In this build every one of its exports
  forwards to `ntoskrnl.exe`. NK is one image answering to both names.
- **File systems are the widest single step** (FAT alone needs several
  hundred names, NTFS and its libraries about three times that) and the
  deepest: they bind to the cache and memory managers.
- **Names are not effort.** The cache manager is a few dozen names and
  among the hardest work here.
- **User mode:** the path to `cmd.exe` uses about half of `ntdll.dll`'s
  system calls, `smss.exe` alone a sixth; the window system has a table
  of its own, nearly three times the size. Phase 6 pins these counts in the
  tree.
- **The Win32 base does not import the window system.** `cmd.exe`,
  `csrss.exe` and its server DLLs import no window or graphics library;
  `conhost.exe` does so only by delay-load. That is why phase 8 can prove
  `cmd.exe` before phase 9 exists. A console without the window system
  might be possible; NK does not pursue it.
- The loader must also handle kernel-mode API sets (`ext-ms-*` names),
  imports by ordinal, and drivers that export to other drivers
  (`msrpc.sys`, `wpprecorder.sys`, `wmilib.sys`, `ksecdd.sys`, `cng.sys`).

## Shape of the kernel

The parts of an NT kernel, and the phase that first builds each:

| NT part | Job | Linux analogue | Phase |
| --- | --- | --- | --- |
| HAL | interrupt controllers, clocks, CPU start, DMA, bus access | `arch/`, irqchip, clocksource | 1, 3 |
| Ke | threads, scheduler, waits, DPCs, APCs, timers, IRQL | `kernel/sched`, softirq, timers | 1 |
| SEH | unwinding and `__try`/`__except` in drivers | (none; C++-style unwind tables) | 2 |
| Ex | pools, resources, push locks, work queues, lookaside lists | slab, rwsem, workqueue | 1, 2 |
| Ob | typed objects, handles, the object namespace | kobject + fd table + a VFS-like tree | 2 |
| Cm | the registry: hive files, keys, values | (none; sysfs + /etc, as a database) | 2, 7 |
| Io | I/O packets, device stacks, file objects, mounting | block/char layers, VFS glue | present, 2, 4 |
| PnP, Po | device tree, driver binding, resources, power | driver core, PM core | 3 |
| Mm | address spaces, sections, faults, MDLs | `mm/` | 4, 6 |
| Cc, FsRtl | file cache and file-system helper library | page cache, `fs/` libs | 4 |
| Ps, Se | processes, threads' user side, tokens, access checks | task, cred, LSM hooks | 2, 6 |
| System calls | the system-call table, user entry and exit, user APCs and exceptions | syscall entry, signals | 6 |
| ALPC | message ports between system processes | AF_UNIX / binder | 7 |
| Session space, callbacks | what `win32k` needs from the kernel | (none) | 9 |

## Phases

In order. 1 and 2 are the trunk. After them, 3 and 5 (hardware) and 4, 6,
7, 8 (toward user mode) depend only on the trunk and on their own
predecessors, so work can alternate; 9 and 10 need both lines.

| # | Phase | NK gains | Proof (unmodified binaries) |
| --- | --- | --- | --- |
| 0 | Ground truth (done) | exact Windows build pinned; reference Windows VM that runs the same test drivers; the corpus pinned by hash and counted in the ledger; private structure layouts checked against public symbols | every later proof has a Windows result to match; the ledger carries the denominator |
| 1 | Kernel core (done: release 0.0.2) | interrupt controllers, clock, every CPU online, IRQL as a real mask, threads, priority scheduler, waits, DPCs, timers, work queues, cancellable requests; a registry in memory and security descriptors, as far as Microsoft's samples ask | Microsoft's `event` and `cancel` samples and the conformance drivers answer as on Windows; the tests pass on 1 to 8 CPUs, repeated under load |
| 2 | **Exceptions, objects, registry** (in progress) | SEH on both architectures; the Ex families its binaries import, with resources and timers; object manager with types, directories and handles; a System process, its token and access checks; registry read from a hive, drivers started from its service keys; export drivers; trace-provider registration | `sioctl` `METHOD_NEITHER`; Microsoft's `wmilib`, `wpprecorder` and `msrpc` libraries load; a named-pipe round trip through `npfs.sys` |
| 3 | Plug and Play, first hardware | PnP and power managers, interrupt connection, DMA, the HAL's private contracts; imports by ordinal and from API sets | `acpi.sys` and `pci.sys` enumerate the machine; sectors read and written through `storport` + `storahci`/`stornvme` + `disk`; first boot on the OptiPlex |
| 4 | Memory, cache, file systems | sections, fault path, paging I/O, cache manager, FsRtl, mounting; APCs | `fastfat.sys` then `ntfs.sys` mount a volume; files read and written; the image checked afterwards by host tools |
| 5 | Frameworks and input | whatever KMDF, USB and HID ask beyond phase 3 | KMDF echo sample; `usbxhci` + hub + HID keyboard on the OptiPlex; `serial.sys` |
| 6 | User mode | user address spaces, image sections, `ntdll.dll`, the system-call table, user APCs and exceptions, user processes and their tokens; `ksecdd.sys` and `cng.sys` | WDK-built native test programs agree with Windows; Microsoft's `autochk.exe` checks a FAT volume |
| 7 | Session manager | ALPC, writable registry, known DLLs, sessions, process creation as `smss.exe` drives it | `smss.exe` runs from a real hive up to starting the Windows subsystem |
| 8 | Win32 base | what `csrss.exe`, its server DLLs, `kernelbase.dll` and `kernel32.dll` ask: the first Win32 processes | `cmd.exe /c ver` with its output redirected to a file |
| 9 | Window system and console | session space, user-mode callbacks, the second system-call table, display through `dxgkrnl.sys` and `BasicDisplay.sys`, `condrv.sys` and `conhost.exe` | `win32k` loads; an interactive `cmd.exe` in its console window |
| 10 | Rescue disk | whatever stock WinPE start-up still asks (`winlogon`, `winpeshl`, services) | the Destination above. Release 0.1.0 |

Phases 1 to 9 each end in a release, 0.0.2 to 0.0.10.

After 0.1.0, unordered: networking (`ndis`, `tcpip`, a NIC driver); booting an unmodified `boot.wim` from a RAM disk; paging to
disk; third-party vendor drivers on the OptiPlex; a full Windows boot to
logon.

## Next step: phase 2

Phase 2 completes the trunk. Built: structured exception handling on
both architectures (`sioctl`'s `METHOD_NEITHER` answers as on Windows),
the object namespace and handles, the System process and its token, the
registry read from a hive, boot drivers started from their service
keys, export drivers. To come: the Ex families, registry enumeration,
trace-provider registration, the access check and the exports over
processes, tokens and objects that the proof binaries import, then the
proofs themselves: Microsoft's libraries load, and a named-pipe round
trip.

Its scope follows what its proof binaries import:

- `npfs.sys` needs no cache manager but does need a process, a token and
  a real access check, so that slice of Ps and Se is built here; user
  processes stay in phase 6.
- No phase-2 binary queues an APC, imports from the kernel by ordinal or from an
  API set; each waits for the phase whose binaries do.
- `ksecdd.sys` and `cng.sys` are full drivers that need virtual memory
  and secure-kernel answers; they load in phase 6.
- Drivers are started the way Windows starts them, from their service
  keys, and boot-start drivers from the hive.

Gaps that stay, each described in `doc/DESIGN.md`: no APCs; the
clock always ticks, at 64 Hz; no priority boosts; a thread can change
only its own priority; the registry is never written back to a file; nothing enforces
a security descriptor; no arm64 `null.sys` (no source; stays SKIP);
never run on a physical machine (phase 3).

## Risks

- **Private layouts and private HAL contracts.** `acpi.sys`, `pci.sys`
  and `win32k` rely on structures and dispatch tables Microsoft does not
  document. Public symbols and the binaries are the only specification.
- **Cache-manager semantics.** ReactOS has not fully run Microsoft's
  `ntfs.sys` after years; the missing pieces were cache and mapping
  routines. FAT comes first for that reason.
- **The exact build.** System-call numbers changed inside the 19041
  family (471 calls at release, 473 later), so user mode and the kernel's
  tables must come from one revision: the pinned 19045.2006.
- **arm64 has no Microsoft binaries.** No public source serves Windows 10
  arm64 files that NK may use. arm64 is proven with WDK-built drivers and
  with x86-64 Windows results that do not depend on the architecture.
- **WinPE's licence.** The deployment kit licenses WinPE only for
  installing and recovering Windows, so it is not used for testing.
  Whether the destination image is WinPE itself or a minimal image built
  from a licensed Windows installation is open, and is the user's
  decision, not NK's.
- **Fixture identity.** The symbol server keys files by timestamp and
  size and may serve a re-signed variant; fixtures are pinned by the hash
  of what was served.
- **No prompt until phase 9.** Phases 6 to 8 are judged by test programs
  and redirected output, not by anything a person can type at. The window
  system pulls in `dxgkrnl.sys` and `watchdog.sys` as well.
- **Security features NK lacks** (hypervisor and secure-kernel helpers,
  code integrity). A driver that asks gets the documented "not present"
  answer; never a pretended success.
