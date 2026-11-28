# Devices

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Devices

What a device's resources mean underneath: configuration space, device
memory, interrupts and DMA. Assigning resources and telling drivers of
them is the Plug and Play manager's; `kernel/hal` and `kernel/mm` are
what the resources stand on.

### PCI configuration space

`kernel/hal/pci.rs`. A function's registers are reached through memory
where the ACPI MCFG table describes them (4096 bytes a function) and
otherwise, on x86-64, through the configuration ports `0xCF8` and
`0xCFC` (256 bytes, segment 0); arm64 has no ports. The memory of every
MCFG entry is mapped once at boot as device memory, in 2 MiB blocks: it
lies above what the direct map covers on the arm64 test machine.

A request is cut into register accesses as wide as its alignment
allows, never across a 32-bit register (`nk_hal::pci::pieces`), all
under one lock at `HIGH_LEVEL`, so configuration space may be read and
written at any IRQL, as Windows allows.

- `hal::pci::read(function, offset, buffer)` and `write` are the
  kernel's own interface: bytes transferred, 0 for a bus that does not
  exist. They say nothing of whether a device is there; an empty slot
  reads as ones.
- [`HalGetBusDataByOffset`](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff546599(v=vs.85))
  and `HalSetBusDataByOffset` serve `PCIConfiguration` alone; other bus
  data reads as absent (0). A function is there if its vendor register
  answers and, for a function other than 0, function 0 says the device
  has several. A read of an empty slot returns the bytes of the vendor
  register it covers, as `PCI_INVALID_VENDORID`: 2 for a read of the
  header, the documented answer. `BusNumber` carries the bus in its low
  eight bits and the segment group in the sixteen above: NK's reading
  for a machine with several segments, the documented one for a machine
  with one.

### Device memory and physical memory

- **Mapping device memory** (`kernel/mm/io.rs`,
  [`MmMapIoSpaceEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmapiospaceex)):
  4 KiB pages in the dynamic region, with the protection asked for.
  Memory that firmware's map does not call RAM is mapped as device
  memory whatever caching is named: uncached on x86-64 (the page
  attribute table's "uncacheable" entry), the device attribute of
  firmware's `MAIR_EL1` on arm64, the strictest it offers. RAM is
  mapped cached unless the protection says otherwise. Write combining
  is mapped as uncached: it makes a run of writes cheaper and changes
  nothing a driver reads.
- **Giving the dynamic region back** (`kernel/mm/map.rs`). The ranges
  handed out are recorded (room for 512 is taken at boot, so the
  record does not grow under drivers and tests). A release must lie
  wholly in one recorded range, else the system stops as Windows'
  `MiReleasePtes` stops for system PTEs that were not allocated:
  `SYSTEM_PTE_MISUSE` (0xDA) with 0x302, the address and the count
  (`MmUnmapIoSpace` checks before it unmaps anything). Part of a range
  may be given back, as on Windows; only a whole range is handed out
  again. Mappings kept for good (device registers the HAL maps) are not
  recorded, so unmapping one stops too.
- **Physical addresses.** `MmGetPhysicalAddress` takes no lock, so it
  is callable at any IRQL: arithmetic for the map of all RAM, else a
  walk of the page tables, which are never freed and whose entries are
  read and written as atomics. `MmGetVirtualForPhysical` answers with
  the address in the map of all RAM, which for pool and contiguous
  memory is the address the memory was handed out at; for an address
  that is not RAM it stops the system.
- **Contiguous memory** (`kernel/mm/contig.rs`) is a pool block of whole
  pages whose frames are one run inside the caller's range of physical
  addresses and across no multiple of its boundary
  (`nk_mm::frames::Within`): counted, checked and freed as pool is. It
  is zeroed, cached and not executable; a caching type is accepted and
  changes nothing, a request for executable memory is refused.
- **MDLs over system memory** (`kernel/io/mdl.rs`).
  `MmBuildMdlForNonPagedPool` reads the buffer's pages from the page
  tables and makes the buffer's own address the MDL's system address;
  mapping such an MDL returns that address and unmapping it does
  nothing. `MmAllocatePagesForMdlEx` takes frames one by one, or in
  aligned runs of `SkipBytes`, from the range asked for, all or none;
  they are mapped nowhere until the driver maps them.
  `MmProtectMdlSystemAddress` rewrites the entries of the MDL's own
  mapping.

### Device interrupts

Three layers, bottom up.

**The controller** (`kernel/arch`). x86-64: the I/O APICs, every input
masked until connected; a redirection register names the vector, the
processor (by APIC id, physical destination) and how the line signals.
ISA interrupts reach their global system interrupt through the MADT's
interrupt source overrides, which also say when one is level triggered
or active low. A message-signalled interrupt is a write to the local
APIC's message address. arm64: the GIC's shared peripheral interrupts,
each given a priority, an edge or level configuration and a route to
one processor; an active-low line is refused, since the GIC cannot be
told. arm64 has no message-signalled interrupts: they need the GIC's
interrupt translation service (LPIs, the ITS's tables and command
queue) or a GICv2m frame, neither of which NK drives.

**Translation** (`kernel/hal/interrupt.rs`). A device's interrupt is
*raw* as firmware or its bus names it and *translated* once it has a
vector, an IRQL and a processor:

| Raw | Translated |
| --- | --- |
| a line: global system interrupt, trigger, polarity | a vector at a device IRQL (3 to 11); on x86-64 a free vector, spread over the IRQLs, whose upper four bits are the IRQL; on arm64 the interrupt id, at an IRQL fixed by the id. Devices on one line get one vector |
| a count of messages (a power of two, at most 16) | that many consecutive vectors of one IRQL, the first a multiple of the count, as a device that adds the message number to its data needs |

`hal::interrupt::translate(raw, affinity)` returns `Translated { level,
vector, affinity }`, the three fields of a translated
`CmResourceTypeInterrupt` descriptor; the affinity is the one processor
chosen, among those allowed and running, by the vector.
`hal::interrupt::release` undoes it, `hal::interrupt::isa` maps an ISA
interrupt to its line, and `hal::interrupt::message` gives the address
and data a bus driver programs into a device for a message vector.
**This is the boundary with the Plug and Play manager:** it calls
`translate` when it builds a device's translated resource list, hands
the list to the driver, and tells `io::interrupt::assign` which
translated interrupts the physical device object has (and `withdraw`
when the device stops), since two of the three ways to connect name
only the device.

On Windows the vectors are not the HAL's to choose: the interrupt
arbiter, in `acpi.sys`, chooses them and has the HAL carry each choice
out (`HalPrivateDispatchTable.HalAddInterruptRemapping`, named for what
it also does under an IOMMU). NK's Plug and Play manager does not ask
that arbiter, but `acpi.sys` runs it for its own system control
interrupt as its device starts: it picks a vector for the line the
FADT names, tells the HAL, stores the result on its physical device
object as interrupt connection data, and connects by line. NK carries
the choice out (`hal::interrupt::assign_line`): the line raises the
vector stated, at the vector's IRQL, on a processor of those stated; a
line NK had translated to another vector is moved, unless an interrupt
object is connected, and its translations find it where it is
(`placed`). On arm64, where a line's vector is its own number, only
that vector is accepted. A message handed to this routine stops the
system: the arbiter places none on NK. The arbiter asks, of every line,
whether it is a secondary interrupt (`HalIsInterruptTypeSecondary`:
never). `HalRemoveInterruptRemapping`, by which the arbiter takes a
choice back, is a trap.

**Interrupt objects** (`kernel/ke/kinterrupt.rs`,
`kernel/io/interrupt.rs`). `IoConnectInterruptEx` (and legacy
`IoConnectInterrupt`, used by drivers such as `serial.sys`) allocates a
`KINTERRUPT`, of the pinned build's layout, and links it into its
vector's chain; the vector's first object unmasks the line, its last
masks it. Fully specified connections name a translated vector and
IRQL; line-based ones use the device's first line, or, for a device
given none as a resource, the first line of the interrupt connection
data a driver stored on it that is placed now (which is where
Windows looks; shared; a value left from interrupts since withdrawn
states nothing, and the connection fails with `STATUS_NOT_FOUND`);
message-based ones
connect every message of the device and return the table of addresses
and data, or fall back to the line when the device has no messages and
say so in the version, as documented.

When the interrupt arrives, on the processor it was routed to, each
routine runs at its object's `SynchronizeIrql` with the object's spin
lock held: one object alone is called once; of several, level
triggered, each in turn until one claims; of several, edge triggered,
all, until a pass in which none claims. An interrupt nobody claims is
counted. `KeSynchronizeExecution` and `KeAcquireInterruptSpinLock` take
the same IRQL and lock. An object reported inactive
(`IoReportInterruptInactive`) is out of its chain until reported active.
Disconnecting waits for the chain's walkers (`doc/LOCKING.md`), so no
routine of a disconnected object is running when it is freed.

### DMA

`kernel/hal/dma.rs`; the arithmetic is `nk_hal::dma`. The machines NK
runs on have no I/O memory management unit and devices that see what
the processor wrote, so a bus address is a physical address and nothing
needs flushing. What an adapter is for is the device that cannot drive
every address bit.

`IoGetDmaAdapter` makes an adapter for a bus master, for a
`DEVICE_DESCRIPTION` of version 0 to 3: the device reaches 64 bits of
address, or 32, or 24, by its two flags, or what version 3's
`DmaAddressWidth` states. It asks no bus driver, since every bus's
addresses are physical addresses here, and it makes none for a device
that is not a bus master: that needs a system DMA controller. The
number of map registers reported is the pages of the device's longest
transfer, plus one. `hal::dma::get_adapter(&Description)` is the same
for the kernel's own callers.

The driver calls through the adapter's table, the pinned build's
`DMA_OPERATIONS`, every slot filled:

- **Common buffers** (`AllocateCommonBuffer`, `...Ex`,
  `...WithBounds`) are contiguous memory within the device's reach and
  the caller's bounds; the logical address is the physical address.
- **Scatter/gather lists** (`GetScatterGatherList`,
  `BuildScatterGatherList`, `CalculateScatterGatherList`,
  `PutScatterGatherList`) name the transfer's own memory, adjacent
  pages joined into one element. A piece the device cannot reach is
  replaced by a bounce page it can, never joined to its neighbours:
  the data is copied there before the device reads it, and from there,
  when the list is put back, after the device wrote it. The buffer a
  list is built in holds the list and, after it, NK's record of the
  bounces, which the list's `Reserved` word points to.
- **Map registers** (`AllocateAdapterChannel`, `MapTransfer`,
  `FlushAdapterBuffers`, `FreeMapRegisters`, `FreeAdapterChannel`) are
  the same bounce pages, one per page of the transfer, allocated with
  the channel when some memory is beyond the device's reach.
  `MapTransfer` returns the memory's own address for as far as it runs
  contiguously within reach, else the page's register.
- Execution routines run at `DISPATCH_LEVEL` before the routine that
  was asked returns: nothing waits for registers. An adapter channel
  the routine keeps makes the next allocation fail with
  `STATUS_INSUFFICIENT_RESOURCES` until it is freed, where Windows
  would queue it.
- `BuildMdlFromScatterGatherList` returns the original MDL for a
  transfer nothing bounced, as documented, and stops the system for
  one that bounced. `FlushDmaBuffer` has nothing to do.
- **Traps**, each naming its slot (`DMA_OPERATIONS.<name>`): the
  operations of a system DMA controller's device (`ReadDmaCounter`,
  `ConfigureAdapterChannel`), the version 3 forms that take a transfer
  context (`InitializeDmaTransferContext`, the `...Ex` channel, map,
  list and flush routines, the two cancels, `GetDmaTransferInfo`,
  `FreeAdapterObject`), DMA domains and common-buffer vectors.

`HalTranslateBusAddress` answers a memory address with itself; an I/O
port address too where the processor has ports, and with failure on
arm64, where NK knows no window through which a bus's ports appear.
