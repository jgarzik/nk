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
- **Running Microsoft's frameworks is cheap at the kernel boundary.**
  Three Microsoft frameworks act as force multipliers: **Storport**
  (already proven with `storahci.sys` and `stornvme.sys`, neither of
  which imports anything directly from `ntoskrnl.exe`), **KMDF**
  (already proven with `wdf01000.sys` and the 9-driver USB/HID stack),
  and **NDIS** (Ethernet/Wi-Fi/virtual NICs and `tcpip.sys`). Writing
  those layers ourselves would cost years and add second ABIs to get wrong.
- **`hal.dll` is a shell.** In this build every one of its exports
  forwards to `ntoskrnl.exe`. NK is one image answering to both names.
- **File systems are the widest single step** (FAT alone needs several
  hundred names, NTFS and its libraries about three times that) and the
  deepest: they bind to the cache and memory managers.
- **Names are not effort.** The cache manager is a few dozen names and
  among the hardest work here; static import percentages do not measure
  private ABI layouts, dynamically looked-up routines, or runtime semantics.
- **User mode:** the path to `cmd.exe` uses about half of `ntdll.dll`'s
  system calls, `smss.exe` alone a sixth; the window system has a table
  of its own, nearly three times the size. `kernel/svc/services.tsv` pins
  all 471 Windows 10 19045.2006 x86-64 system services, and `ledger/x86_64.json`
  (`services`) records every registered SSDT entry.
- **The Win32 base does not import the window system.** `cmd.exe`,
  `csrss.exe` and its server DLLs import no window or graphics library;
  `conhost.exe` does so only by delay-load. That is why phase 8 can prove
  `cmd.exe` before phase 9 exists. A console without the window system
  might be possible; NK does not pursue it. Note also that stock WinPE
  `wpeinit.exe` invokes Plug and Play and networking initialization, so
  proving an offline `cmd.exe` shell is distinct from completing every
  stock `wpeinit.exe` step.
- **High-priority Microsoft subsystem imports:** `ledger/x86_64.json`
  (`corpus.high_priority`) explicitly tracks and prioritizes closing the
  kernel-export gaps of five core Microsoft subsystems: `storport.sys`
  (storage port — already running with `storahci.sys` and `stornvme.sys`,
  closing remaining `partial`/`traps` entries), `ndis.sys`, `tcpip.sys`,
  and `afd.sys` (networking and Winsock stack, along with `netio.sys`,
  `fwpkclnt.sys`, and `tdi.sys`), and `ntfs.sys` (NTFS, along with
  `clfs.sys` via `ext-ms-win-fs-clfs-l1-1-0.dll`), plus `shared_gaps`
  ranking non-implemented exports needed by two or more priority
  subsystems. Run `tools/ledger.py --priority` for the live gap breakdown.
- Besides drivers that export to drivers, which NK binds, the loader
  must handle kernel-mode API sets (`ext-ms-*` names) and imports from
  the kernel by ordinal (`acpi.sys` has one).

## Shape of the kernel

The parts of an NT kernel still to build, and the phase that builds
each. What NK already has (through Phase 6 user mode) is in `README.md`
and `doc/design/`.

| NT part | To build | Linux analogue | Phase |
| --- | --- | --- | --- |
| Cm | a registry that is written back | (none; sysfs + /etc, as a database) | 7 |
| ALPC | message ports between system processes | AF_UNIX / binder | 7 |
| Session space, callbacks | what `win32k` needs from the kernel | (none) | 9 |

## Phases

In order, from here to the rescue disk (Phases 0–6, including the
foundation for user mode and native user mode with unmodified
`ntdll.dll` and `autochk.exe`, are proven and listed in `README.md`).

| # | Phase | NK gains | Proof (unmodified binaries) |
| --- | --- | --- | --- |
| 7 | Session manager | ALPC, writable registry, sessions, process creation as `smss.exe` drives it | `smss.exe` runs from a real hive up to starting the Windows subsystem |
| 8 | Win32 base | what `csrss.exe`, its server DLLs, `kernelbase.dll` and `kernel32.dll` ask: the first Win32 processes | `cmd.exe /c ver` with its output redirected to a file |
| 9 | Window system and console | session space, user-mode callbacks, the second system-call table, display through `dxgkrnl.sys` and `BasicDisplay.sys`, `condrv.sys` and `conhost.exe` | `win32k` loads; an interactive `cmd.exe` in its console window |
| 10 | Rescue disk | whatever stock WinPE start-up still asks (`winlogon`, `winpeshl`, `wpeinit`, services); release images without the boot self-tests; full interactive bare-metal boot on the Dell OptiPlex | the Destination above |

### Parallel and post-rescue-disk tracks

- **Early bare-metal bring-up (decoupled from Phase 10):** physical boot
  on the Dell OptiPlex 3020 SFF (Intel H81, SATA/AHCI via `storahci.sys`
  rather than NVMe, USB xHCI, Realtek Gigabit Ethernet) can proceed in
  parallel with Phases 7–9 without waiting for userspace or graphics,
  exposing real ACPI, PCI, interrupt, and DMA edge cases early. Add a
  second physical machine (modern AMD or NVMe-equipped PC) once the
  OptiPlex boots to guard against single-machine overfitting.
- **Graduated networking bring-up:** rather than targeting full WinPE
  networking at once, bring up Microsoft's networking binaries in four
  stages:
  1. Load unmodified `ndis.sys` and initialize a Windows NIC miniport
     under QEMU, sending/receiving Ethernet frames with a WDK protocol
     test driver.
  2. Load `tcpip.sys` (with `netio.sys` / `fwpkclnt.sys`) and verify
     loopback, static IPv4, ICMP, and a kernel-mode TCP echo server via
     Microsoft's Winsock Kernel (WSK) sample.
  3. Load `afd.sys` and verify unmodified userspace Winsock (`ws2_32.dll`)
     TCP/UDP applications.
  4. Bring up DHCP, DNS, IPv6, stock Windows networking services, and the
     physical Realtek NDIS driver on the OptiPlex.
- **Three-stage driver discovery and installation:**
  1. Early physical boot: manually staged boot drivers and registry keys.
  2. Multiple PC models: reuse driver-database records harvested from
     reference Windows installations.
  3. General hardware compatibility: run Microsoft's own userspace PnP
     device installation and Driver Store infrastructure on NK rather
     than building an NK-native INF installer.
- **Other post-rescue-disk goals (unordered):** `ntfs.sys`; booting an
  unmodified `boot.wim` from a RAM disk; paging to disk; third-party
  vendor drivers; a full Windows boot to interactive logon. Across all
  phases, closing the kernel-export gaps needed by `storport.sys`,
  `tcpip.sys`, `ndis.sys`, `afd.sys`, and `ntfs.sys` is tracked as
  high-priority work in `ledger/x86_64.json` (`corpus.high_priority`).

## Next step: Phase 7 (Session manager)

The detailed plan for Phase 7 (`smss.exe`, ALPC, writable registry,
sessions) will be written here when work begins. What NK lacks is
listed in `doc/design/absent.md`.

## Risks

- **Private layouts and private HAL contracts.** `acpi.sys`, `pci.sys`
  and `win32k` rely on structures and dispatch tables Microsoft does not
  document. Public symbols and the binaries are the only specification.
- **NTFS depth beyond static imports.** `ntfs.sys` imports over 600
  kernel routines and exercises cache coherency, lazy writing, paging I/O,
  mapped-section synchronization, byte-range locking, oplocks, security
  descriptors, filesystem filters, and KTM/CLFS transaction logging and
  crash recovery. FAT comes first for that reason.
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
