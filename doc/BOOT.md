# Boot

How control gets from firmware to the kernel, and what the kernel can
assume when it starts. The handoff structure is defined, with comments,
in `lib/bootinfo/lib.rs`.

## The EFI system partition

```
\EFI\BOOT\BOOTX64.EFI     nkload on x86-64 (BOOTAA64.EFI on arm64)
\NK\nkkrnl.exe            the kernel
\NK\drivers\*.sys         boot drivers
\NK\cmdline.txt           optional: the kernel command line
```

`tools/mkesp.py` builds it. Firmware starts the `\EFI\BOOT` file because
it is the default path for a volume with no boot entry.

## What nkload does

1. Reads the kernel and every file in `\NK\drivers` into memory, and
   the command line if there is one: a single line of `key=value` words
   (`doc/TESTING.md` lists them), at most 255 ASCII characters.
2. Maps the kernel image with `lib/pe` and relocates it to its fixed
   virtual base. The kernel links at a low default base on purpose, so the
   relocation path runs on every boot.
3. Finds the serial console (ACPI SPCR table; a per-architecture default
   if there is none) and the ACPI RSDP.
4. Builds page tables.
5. Calls `ExitBootServices`, then switches tables and jumps.

If anything fails, nkload prints an `NK-TEST boot:FAIL` line and powers
off: a broken boot is a fast test failure, not a hang.

## Address space at kernel entry

nkload builds the direct map and the kernel image's mapping; the table
of ranges is in `doc/DESIGN.md` (Address space). The low half holds only
an identity map of firmware runtime regions, and differs by architecture:


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

- Boot CPU only, interrupts masked, on a 32 KiB stack in the direct map
  whose top is a multiple of 64 KiB: the size and alignment of every
  kernel stack (`nk_bootinfo::KERNEL_STACK_SIZE`).
- One argument: a pointer to `BootInfo`.
- x86-64: `EFER.NXE` and `CR0.WP` set. arm64: EL1.
- Memory the loader allocated (kernel image, page tables, stack,
  `BootInfo`, driver files, the memory map itself) is typed
  `EfiLoaderData` in the memory map.

## Power off

The kernel calls UEFI `ResetSystem` at its physical address through the
identity map. The same path works on QEMU for both architectures and on
real hardware. NK never calls `SetVirtualAddressMap`.

Every call into firmware's runtime code is made through one function,
`hal::firmware_call`, on whichever processor and stack the caller is on;
an architecture hook on each side of the call makes the address space
what runtime code needs and puts it back.

## Known limits

- Firmware runtime code regions are mapped writable and executable,
  because runtime driver images mix code and data.
- The direct map is a writable alias of all RAM, kernel text included, so
  the image's read-only mappings stop accidents, not a determined write.
- On arm64 firmware's full identity map is still live in `TTBR0`.
- The loader's boot stack has ordinary memory below it. The kernel
  leaves it for a guarded stack of its own as soon as it can allocate
  one; until then an overflow is caught on arm64 (by the alignment rule)
  but not on x86-64.
