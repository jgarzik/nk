# Roadmap

The phases from NK to a Windows rescue disk: Microsoft's Windows
10 user mode at a `cmd.exe` prompt on a kernel that is entirely NK. This
file fixes the order, its reason, and what proves each phase; a phase
gets a detailed plan when it starts, and leaves this file when it is
proven. What NK is and its principles:
`doc/DESIGN.md`. What runs: `README.md`.

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
- Besides drivers that export to drivers, which NK binds, the loader
  must handle kernel-mode API sets (`ext-ms-*` names) and imports from
  the kernel by ordinal (`acpi.sys` has one).

## Shape of the kernel

The parts of an NT kernel still to build, and the phase that builds
each. What NK has of each part is in `doc/DESIGN.md`.

| NT part | To build | Linux analogue | Phase |
| --- | --- | --- | --- |
| HAL | device interrupts, DMA, bus access, the tables `acpi.sys` and `pci.sys` call it through | `arch/`, irqchip | 3 |
| PnP, Po | device tree, driver binding, resources, power | driver core, PM core | 3 |
| Io | device stacks; mounting | block/char layers, VFS glue | 3, 4 |
| Ke | APCs | signals, task work | 4 |
| Mm | sections, faults, paging I/O; user address spaces | `mm/` | 4, 6 |
| Cc, FsRtl | file cache and the file-system helper library | page cache, `fs/` libs | 4 |
| Ps, Se | user processes and their tokens | task, cred, LSM hooks | 6 |
| System calls | the system-call table, user entry and exit, user APCs and exceptions | syscall entry, signals | 6 |
| Cm | a registry that is written back | (none; sysfs + /etc, as a database) | 7 |
| ALPC | message ports between system processes | AF_UNIX / binder | 7 |
| Session space, callbacks | what `win32k` needs from the kernel | (none) | 9 |

## Phases

In order. Phase 4 mounts FAT on the disk phase 3 delivers, so hardware
and file systems are one line up to there. After it, 5 (more hardware)
and 6, 7, 8 (toward user mode) depend only on their own predecessors, so
work can alternate; 9 and 10 need both. QEMU proves a phase first; the
OptiPlex follows.

| # | Phase | NK gains | Proof (unmodified binaries) |
| --- | --- | --- | --- |
| 3 | Plug and Play, first hardware | PnP and power managers, interrupt connection, DMA, the HAL's private contracts; imports by ordinal and from API sets | `acpi.sys` and `pci.sys` enumerate QEMU's q35 machine; sectors read and written on its AHCI controller through `storport` + `storahci` + `disk`, and checked in the disk image afterwards |
| 4 | Volumes, memory, cache, FAT | partition and volume discovery; the libraries `fastfat.sys` imports from (`ksecdd.sys`, `msrpc.sys`, API sets); sections, fault path, paging I/O, cache manager, FsRtl, mounting; APCs | `partmgr.sys`, `volmgr.sys` and `mountmgr.sys` find the volume on phase 3's disk; `fastfat.sys` mounts it; files read and written; the image checked afterwards by host tools |
| 5 | Frameworks and input | whatever KMDF, USB and HID ask beyond phase 3 | KMDF echo sample; first boot on the OptiPlex: its disk through `stornvme`, `usbxhci` + hub + HID keyboard; `serial.sys` |
| 6 | User mode | user address spaces, image sections, `ntdll.dll`, the system-call table, user APCs and exceptions, user processes and their tokens; `cng.sys` | WDK-built native test programs agree with Windows; Microsoft's `autochk.exe` checks a FAT volume |
| 7 | Session manager | ALPC, writable registry, known DLLs, sessions, process creation as `smss.exe` drives it | `smss.exe` runs from a real hive up to starting the Windows subsystem |
| 8 | Win32 base | what `csrss.exe`, its server DLLs, `kernelbase.dll` and `kernel32.dll` ask: the first Win32 processes | `cmd.exe /c ver` with its output redirected to a file |
| 9 | Window system and console | session space, user-mode callbacks, the second system-call table, display through `dxgkrnl.sys` and `BasicDisplay.sys`, `condrv.sys` and `conhost.exe` | `win32k` loads; an interactive `cmd.exe` in its console window |
| 10 | Rescue disk | whatever stock WinPE start-up still asks (`winlogon`, `winpeshl`, services) | the Destination above |

After the rescue disk, unordered: `ntfs.sys`; networking (`ndis`, `tcpip`, a NIC driver); booting an unmodified `boot.wim` from a RAM disk; paging to
disk; third-party vendor drivers on the OptiPlex; a full Windows boot to
logon.

## Next step: phase 3

Phase 3 takes NK onto hardware, under QEMU: Microsoft's `acpi.sys` and
`pci.sys` enumerate the q35 machine, and sectors of a disk on its AHCI
controller are read and written through `storport.sys`, with
`storahci.sys` beneath it and `disk.sys` above. Finding partitions and
volumes on that disk opens phase 4.

Its scope follows what its proof binaries import
(`tools/ledger.py --missing acpi.sys pci.sys storport.sys classpnp.sys disk.sys`):

- Plug and Play builds the device tree and device stacks and sends the
  start and enumeration requests these drivers expect
  (`IoInvalidateDeviceRelations`).
- Device interrupts are connected (`IoConnectInterruptEx`) through the
  controllers NK drives; DMA goes through the HAL's adapter interface
  (`IoGetDmaAdapter`).
- `acpi.sys` and `pci.sys` call the HAL through its private tables
  (`HalDispatchTable`, `HalPrivateDispatchTable`); public symbols and the
  binaries are the only specification (Risks).
- The loader binds imports from the kernel by ordinal and kernel-mode
  API-set names (`ext-ms-win-ntos-ksr-*`), and loads `pshed.dll`, which
  `pci.sys` imports from.
- The miniports import from `storport.sys` alone, and `disk.sys` from
  `classpnp.sys` and the kernel: Microsoft's own libraries carry them.
- No phase-3 binary queues an APC or imports a cache or section routine;
  those wait for phase 4.
- arm64 has no Microsoft binaries: its share is the same managers,
  proven with NK's own test drivers inside the kernel.

What NK lacks is listed in `doc/DESIGN.md` ("What is absent").

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
