# Roadmap

One sequence of phases from today's NK to a Windows rescue disk: real
Windows 10 user mode at a `cmd.exe` prompt, on a kernel that is entirely
NK. Each phase gets its own detailed plan when it starts; this file only
fixes the order, the reason for the order, and what proves a phase done.

The one rule that outranks everything here: **an unmodified Windows
driver binary must not be able to tell NK from Windows.**

## Where NK is

On QEMU, x86-64 and arm64: UEFI boot through NK's own loader, own page
tables, a pool, a PE loader with import binding, driver/device/file
objects, synchronous IRPs with completion routines and MDLs; interrupt
controllers, the IRQL as their priority mask, a clock, every processor
running, DPCs, timers, preemptive threads, waits on events, semaphores,
timers and mutexes, kernel handles. Microsoft's
`null.sys` (x86-64) and the WDK-built `sioctl.sys` (both) load, do I/O and
unload without leaks.

Not there: device interrupts, APCs, asynchronous I/O,
structured exception
handling, Plug and Play, any hardware device, user mode. Open
gaps carried into the phases below: no arm64 `null.sys` (no usable
source; stays SKIP), `METHOD_NEITHER` untested (phase 2), never run on a
physical machine (phase 3). The two drivers' results match a run on real
Windows, request by request (`oracle/`).

## Destination

A FAT32 volume holding Microsoft's Windows PE image, applied flat
([Microsoft's "flat boot"](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-install-on-a-hard-drive--flat-boot-or-non-ram)),
booted by `nkload` and NK in place of Microsoft's boot manager, loader,
kernel and HAL. Every other file is Microsoft's and unmodified. It reaches
the `X:\windows\system32>` prompt on QEMU x86-64 and on the Dell OptiPlex,
and on QEMU arm64 once arm64 Windows files can be obtained.

Flat boot is the target because it needs the fewest drivers: no RAM disk,
no WIM filter, no NTFS. Booting an untouched `boot.wim` comes after.

## Decisions

| Question | Decision |
| --- | --- |
| Whose user mode? | Microsoft's real binaries, from Microsoft's media. NK ships none of them. |
| Whose PCI, ACPI, storage, file-system, network and framework drivers? | Microsoft's. NK is the kernel and HAL only; the golden rule applies to Microsoft's own drivers too. |
| Which Windows? | The Windows 10 2004-22H2 family (one code base, 19041). Drivers built for any of it must run. |
| Which exact build? | Windows 10 Enterprise 22H2, 10.0.19045.2006: the build of Microsoft's evaluation ISO. The reference VM is installed from that ISO and fixture versions follow it. One revision supplies user mode, the system-call numbers and the private layouts. |
| Where do Windows files come from? | x86-64 files one by one from Microsoft's symbol server, pinned by SHA-256; the reference VM from the evaluation ISO. Microsoft's deployment kit (WinPE) is not used for testing: its licence allows WinPE only for installing and recovering Windows. |
| First prompt | In the real console window (phase 9). No effort goes into a console without the window system. |
| Code from hk | None. hk is read as a reference; NK's code is written fresh. |
| arm64 | First class for all NK code: every commit builds and boots both. Proofs that need a Microsoft arm64 binary nobody can fetch print SKIP until the supply is solved. |
| Sources for undocumented behaviour | Microsoft's public symbols, reading the fixture binaries, a reference Windows VM, and reading ReactOS and Wine for understanding. No code copied or translated from them; never leaked source. |

## Measurements

58 kernel-mode binaries of the pinned build (x86-64) are listed in
`fixtures/corpus.toml`: Microsoft's drivers and the libraries they import
from. `tools/corpus.py` fetches them from Microsoft's symbol server and
writes down what each imports; `ledger/x86_64.json` counts, per binary,
how much of that NK provides. Counts below are distinct names imported
from `ntoskrnl.exe` and `hal.dll`.

| Corpus, growing | Names needed |
| --- | --- |
| `null`, `sioctl` | 14 |
| `fastfat.sys` alone | 326 |
| + `ntfs`, `fltmgr`, `ksecdd`, `cng`, `clfs` | 919 |
| + ACPI, PCI, storport, AHCI, NVMe, disk, partition, volume, mount manager | 1237 |
| + KMDF (`wdf01000`, `wdfldr`) | 1254 |
| + named pipes, mailslots, console driver, PS/2, keyboard, serial | 1302 |
| + USB 3 host, hub, HID | 1325 |
| + NDIS, TCP/IP, sockets | 1427 |
| + `win32k`, `win32kbase`, `win32kfull` | 1630 |
| the whole corpus | 1740 (of the kernel's roughly 3070 named exports) |

The user-mode counts further down are from a later servicing build and
are not yet reproducible from the tree; phase 6 pins them.

What the numbers say:

- **Running Microsoft's frameworks is cheap at the kernel boundary.** KMDF
  adds 17 names and the USB stack 23, because the Microsoft binaries
  carry the rest. `storahci.sys` imports nothing from the kernel at all,
  only from `storport.sys`. Writing those layers ourselves would cost
  years and add a second ABI to get wrong.
- **`hal.dll` is a shell.** In this build all 91 of its exports forward to
  `ntoskrnl.exe`. NK is one image answering to both names.
- **File systems are the widest single step** (326 names for FAT, 919 with
  NTFS) and the deepest: they bind to the cache and memory managers.
- **Names are not effort.** The cache manager is 47 names and among the
  hardest work here.
- **User mode:** `ntdll.dll` has 473 system calls. `smss.exe` uses 76;
  the path to `cmd.exe` about 242. The window system adds 1318 more.
- **The Win32 base does not import the window system.** `cmd.exe`,
  `csrss.exe` and its server DLLs import no window or graphics library;
  `conhost.exe` does so only by delay-load. That is why phase 8 can prove
  `cmd.exe` before phase 9 exists. A console without the window system
  might be possible; NK does not pursue it.
- The loader must also handle kernel-mode API sets (`ext-ms-*` names),
  imports by ordinal, and drivers that export to other drivers
  (`msrpc.sys`, `wpprecorder.sys`, `wmilib.sys`, `ksecdd.sys`, `cng.sys`).

## Shape of the kernel

`doc/DESIGN.md` states what NK is and the principles every phase follows.
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
| Ps, Se | processes, threads' user side, tokens, access checks | task, cred, LSM hooks | 6 |
| System calls | the 473-entry table, user entry and exit, user APCs and exceptions | syscall entry, signals | 6 |
| ALPC | message ports between system processes | AF_UNIX / binder | 7 |
| Session space, callbacks | what `win32k` needs from the kernel | (none) | 9 |

## Phases

In order. 1 and 2 are the trunk. After them, 3 and 5 (hardware) and 4, 6,
7, 8 (toward user mode) depend only on the trunk and on their own
predecessors, so work can alternate; 9 and 10 need both lines.

| # | Phase | NK gains | Proof (unmodified binaries) |
| --- | --- | --- | --- |
| 0 | Ground truth | exact Windows build pinned; reference Windows VM that runs the same test drivers; the corpus pinned by hash and counted in the ledger; private structure layouts checked against public symbols | every later proof has a Windows result to match; ledger shows 14 of 1740 |
| 1 | **Kernel core** (in progress) | interrupt controllers, clock, every CPU online, IRQL as a real mask, threads, priority scheduler, waits, DPCs, APCs, timers, work queues | WDK samples that block, queue work and use timers; asynchronous IRPs; the existing tests under all CPUs |
| 2 | Exceptions, objects, registry | SEH on both architectures; the rest of Ex; object manager with handles and directories; registry read from a real hive; API sets, ordinal imports, export drivers; trace-provider registration | `sioctl` `METHOD_NEITHER`; Microsoft's support libraries load; a named-pipe round trip through `npfs.sys` |
| 3 | Plug and Play, first hardware | PnP and power managers, interrupt connection, DMA, the HAL's private contracts | `acpi.sys` and `pci.sys` enumerate the machine; sectors read and written through `storport` + `storahci`/`stornvme` + `disk`; first boot on the OptiPlex |
| 4 | Memory, cache, file systems | sections, fault path, paging I/O, cache manager, FsRtl, mounting | `fastfat.sys` then `ntfs.sys` mount a volume; files read and written; the image checked afterwards by host tools |
| 5 | Frameworks and input | whatever KMDF, USB and HID ask beyond phase 3 | KMDF echo sample; `usbxhci` + hub + HID keyboard on the OptiPlex; `serial.sys` |
| 6 | User mode | user address spaces, image sections, `ntdll.dll`, the system-call table, user APCs and exceptions, tokens | WDK-built native test programs agree with Windows; Microsoft's `autochk.exe` checks a FAT volume |
| 7 | Session manager | ALPC, writable registry, known DLLs, sessions, process creation as `smss.exe` drives it | `smss.exe` runs from a real hive up to starting the Windows subsystem |
| 8 | Win32 base | what `csrss.exe`, its server DLLs, `kernelbase.dll` and `kernel32.dll` ask: the first Win32 processes | `cmd.exe /c ver` with its output redirected to a file |
| 9 | Window system and console | session space, user-mode callbacks, the second system-call table, display through `dxgkrnl.sys` and `BasicDisplay.sys`, `condrv.sys` and `conhost.exe` | `win32k` loads; an interactive `cmd.exe` in its console window |
| 10 | Rescue disk | whatever stock WinPE start-up still asks (`winlogon`, `winpeshl`, services) | the Destination above. Release 0.1.0 |

Phases 1 to 9 each end in a release, 0.0.2 to 0.0.10.

After 0.1.0, unordered: networking (`ndis`, `tcpip`, a NIC driver: 102
more names); booting an unmodified `boot.wim` from a RAM disk; paging to
disk; third-party vendor drivers on the OptiPlex; a full Windows boot to
logon.

## Next step: phases 0 and 1

Phase 1, the kernel core, is next because every other phase lists it as a
prerequisite. It is also NK's sharpest limit: a driver that returns
"pending" cannot be waited for, and no hardware driver can run without
interrupts and DPCs. Inside the phase:

1. Interrupt controllers and the clock on the boot CPU, both
   architectures.
2. The other CPUs, before the scheduler exists, so that per-CPU state,
   IRQL and cross-CPU interrupts are right before code depends on them.
3. Threads, the scheduler and waits, written for many CPUs from the first
   commit.
4. DPCs, timers, work queues, APCs, and the drivers that prove them.

The pin and the symbol-derived layout tables of phase 0 come first, by a
few days: phase 1 fixes the thread and processor structures, and those
must have Windows' shape. The rest of phase 0 runs alongside.

SEH is deliberately second, not first: nothing in phase 1's proofs needs
it, and it needs no hardware. It must not slip later than phase 2, since
file systems use it on every path.

Recorded gaps of phase 1: the clock always ticks (no tickless idle), and
its rate is fixed at 64 Hz; thread priorities are not boosted.

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
- **WinPE's licence.** The destination is a WinPE-style rescue disk, but
  the deployment kit licenses WinPE only for installing and recovering
  Windows. Whether the destination image is WinPE itself or a minimal
  image built from a licensed Windows installation is open, and is the
  user's decision, not NK's.
- **Fixture identity.** The symbol server keys files by timestamp and
  size and may serve a re-signed variant; fixtures are pinned by the hash
  of what was served.
- **No prompt until phase 9.** Phases 6 to 8 are judged by test programs
  and redirected output, not by anything a person can type at. The window
  system pulls in `dxgkrnl.sys` and `watchdog.sys` as well.
- **Security features NK lacks** (hypervisor and secure-kernel helpers,
  code integrity). A driver that asks gets the documented "not present"
  answer; never a pretended success.
