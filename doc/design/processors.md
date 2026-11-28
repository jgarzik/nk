# Processors, interrupts and time

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Processors

`kernel/hal/platform.rs` reads the ACPI MADT once: the usable processors
and the interrupt controllers (local and I/O APICs; GIC distributor and
redistributors). The boot processor is number 0; at most 64 are kept, one
Windows processor group.

The boot processor starts the others one at a time and waits for each; one
that does not report is a failed boot, never a smaller machine. x86-64:
INIT and start-up interrupts into a real-mode trampoline copied below
1 MiB, which climbs to long mode on the kernel's page tables. arm64: PSCI
`CPU_ON` (by the call the FADT names) into a stub that runs with the MMU
off on a table mapping only its own page, then adopts the boot
processor's translation settings and NK's low half.

Each processor has its own area, the PCR at its start and NK's `PerCpu`
(held locks, DPC queue, timer table, ready queues) beside it, allocated
before the processor starts. Each brings up its own interrupt controller
and clock interrupt; processor 0 alone keeps the time. The context a
processor starts in becomes its idle thread.

`ke::ipi` runs a routine on other processors at IRQL 14 and waits for all
of them; one call is in progress at a time. A processor silent for five
seconds is stuck with interrupts off, and the system stops. x86-64 uses
this to drop a translation everywhere on unmap; arm64's invalidation
broadcasts by itself. `KeIpiGenericCall` is one such call whose routine
holds each processor until all have been interrupted and only then runs
the driver's function, on all at once: drivers use it to do something
while nothing else in the system runs.

The processor that stops the system stops the others first: by NMI on
x86-64, by the most urgent software-generated interrupt on arm64 (which a
processor with interrupts fully masked does not take). A second processor
reaching a bugcheck halts silently, so one report is printed.

## Interrupts

Each controller comes up with everything masked that NK did not ask for:
the local APIC (x2APIC when available) with the 8259s and every I/O APIC
input masked; GICv3, where a processor finds its redistributor by
affinity, not position. The IRQL is the controller's priority mask;
levels and vectors are in `doc/LOCKING.md`. The kernel's own interrupts
are the clock and ones a processor sends itself or another; a device's
are in [Devices](devices.md).

Each processor folds the cycle count at which a device interrupt
arrives into a buffer of 64 words, as Windows does
(`kernel/ke/entropy.rs`): one driver, `cng.sys`, registers a routine
for it with `ZwSetSystemInformation` (class 0x83), its initialisation
routine is run over every processor's state, and from then on each
1024th interrupt on a processor queues a DPC there that hands the
routine the half of the buffer just filled. A second registration is
refused, as on Windows. The state is NK's own per-processor record;
the driver sees it only through the pointers it is given.

A processor fault is an exception for the faulting code's handlers
([Exceptions](exceptions.md)) or a bugcheck with a register dump.

## Time

One free-running counter is the source of all time: the TSC on x86-64,
its rate measured against the ACPI PM timer at boot; the generic timer's
counter on arm64, which states its rate. The clock interrupt fires 64
times a second (Windows' default) at IRQL 13, from the local APIC timer
or the generic timer's virtual timer. Each tick recomputes time from the
counter rather than counting ticks, so a late or lost tick costs nothing.

WDK-built code reads tick count, interrupt time and system time in line
from `KUSER_SHARED_DATA`; the tick keeps that page current. The wall
clock starts from firmware's time, read by the loader.
