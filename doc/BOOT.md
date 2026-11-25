# Boot

How control gets from firmware to the kernel, and what the kernel can
assume when it starts. The handoff structure is defined, with comments,
in `lib/bootinfo/lib.rs`.

## The EFI system partition

```
\EFI\BOOT\BOOTX64.EFI     nkload on x86-64 (BOOTAA64.EFI on arm64)
\NK\nkkrnl.exe            the kernel
\NK\drivers\*.sys         boot drivers
```

`tools/mkesp.py` builds it. Firmware starts the `\EFI\BOOT` file because
it is the default path for a volume with no boot entry.

## What nkload does

1. Reads the kernel and every file in `\NK\drivers` into memory.
2. Maps the kernel image with `lib/pe` and relocates it to its fixed
   virtual base. The kernel links at a low default base on purpose, so the
   relocation path runs on every boot.
3. Finds the serial console (ACPI SPCR table; a per-architecture default
   if there is none) and the ACPI RSDP.
4. Builds page tables.
5. Calls `ExitBootServices`, then switches tables and jumps.

If anything fails, nkload prints an `NK-TEST boot:FAIL` line and powers
off, so a broken boot is a fast, visible test failure rather than a hang.

## Address space at kernel entry

| Range | Contents |
| --- | --- |
| `0xFFFF_8000_0000_0000` + phys | Direct map of physical memory, 2 MiB blocks, not executable. Ranges with no RAM are mapped as device memory. |
| `0xFFFF_F800_0000_0000` | The kernel image, 4 KiB pages, each with its section's protection (text read+execute, data read+write, the rest read-only). |
| Low half | Identity map of firmware runtime regions only, kept so UEFI runtime services stay callable. |

The low half differs by architecture:

- **x86-64:** nkload builds the identity map itself, in the same tables.
  It covers the regions firmware marks as needed at runtime (code
  executable, data not) and the loader's own code, which is still running
  when the tables are switched. Page zero and ordinary RAM are not mapped
  there, so a null dereference faults.
- **arm64:** firmware's own identity map stays in `TTBR0`; nkload only
  installs the kernel half in `TTBR1`. Firmware is running with the MMU
  on, and nkload keeps firmware's `MAIR_EL1` rather than change memory
  attributes under live mappings. It looks up which attribute indices
  mean normal and device memory and passes them in `BootInfo`.

## State at kernel entry

- Boot CPU only, interrupts masked, on a 64 KiB stack in the direct map.
- One argument: a pointer to `BootInfo`.
- x86-64: `EFER.NXE` and `CR0.WP` set. arm64: EL1.
- Memory the loader allocated (kernel image, page tables, stack,
  `BootInfo`, driver files, the memory map itself) is typed
  `EfiLoaderData` in the memory map.

## Power off

The kernel calls UEFI `ResetSystem` at its physical address through the
identity map. The same path works on QEMU for both architectures and on
real hardware. NK never calls `SetVirtualAddressMap`.

## Known limits

- Firmware runtime code regions are mapped writable and executable,
  because runtime driver images mix code and data.
- The direct map is a writable alias of all RAM, kernel text included, so
  the image's read-only mappings stop accidents, not a determined write.
- On arm64 firmware's full identity map is still live in `TTBR0`.
- The boot stack has no guard page.
