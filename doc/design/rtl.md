# Strings and the runtime library

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Strings

The rules are `lib/rtl`; the exports in `kernel/rtl` read and write a
driver's strings where they lie. A routine that cannot fail (a
comparison, a search, `RtlCompareMemory`) takes its input one unit at a
time and stops at the unit that decides the answer, so it needs neither
a copy nor memory for one. Strings the routines allocate come from the
pool and are freed by `RtlFreeUnicodeString` or `RtlFreeAnsiString`.

- **The ANSI code page is Windows-1252**, the page of the reference
  machine's English (United States) installation, compiled in
  (`nk_rtl::codepage`); the registry's `Nls\CodePage` key is not
  consulted. A character the page lacks becomes its best fit by
  Windows' table (a fullwidth or accented letter to its plain form),
  recorded from Windows 10 like the upper-case table, and `?` where
  that has none.
- **The OEM code page is 437**, the same installation's
  (`nk_rtl::codepage::OEM_437`, from the Unicode Consortium's table),
  in which FAT keeps short names. Every byte maps both ways. Windows
  best-fits some characters 437 lacks; NK has no record of those, so
  each becomes `?`, and a conversion to a counted OEM string reports
  `STATUS_UNMAPPABLE_CHARACTER` for it, as Windows does for a character
  with no best fit. The variables file systems read say 437 has no
  double-byte characters (`kernel/rtl/nls.rs`).
- **Short names** (`RtlGenerate8dot3Name`, `nk_rtl::gen83`) are
  Windows' to the character, read from the pinned kernel: the base,
  the numbering, the checksum (`RtlComputeLfnChecksum`) and when it is
  used, and the end of the numbers. Whether an extension of more than
  three characters ends in `~` comes from the registry's
  `Control\FileSystem\Win95TruncatedExtensions`, read at boot as
  Windows reads it (`fsrtl::init`).
- **Upper case** is one table, `nk_rtl::upcase`: Windows' own, every
  unit as `RtlUpcaseUnicodeChar` answers on Windows 10, recorded there
  by the conformance driver `nkc-rtl`. It is older than the Unicode
  character database and leaves alone some units that maps (the micro
  sign, dotless i, long s, final sigma, Georgian). The string
  comparisons, the object namespace and the registry all use it.
- **The C runtime's comparisons** (`_stricmp`, `_strnicmp`, `_wcsicmp`,
  `_wcsnicmp`) fold `A` to `Z` only and do not use that table; `_strupr`
  and `isspace` are the C locale's too. `RtlCompareString` does use it,
  through the ANSI page: a byte's upper case is the byte of its unit's.
- **The C runtime has no invalid-parameter handler.** A bounded copy
  (`strncpy_s`) given a bad argument empties its destination and returns
  the error number. `rand` has one seed for the whole system.
- **Length rules read from Windows.** When a routine stores a length
  before it knows the text fits, when it writes a terminator, and what
  it makes of a string too long to count are stated in
  `nk_rtl::counted`, `nk_rtl::codepage` and `nk_rtl::convert`, with what
  is still NK's inference marked there.

### File names

`FsRtlIsNameInExpression` and `FsRtlLegalAnsiCharacterArray` are
exported from `kernel/rtl` with the strings they work on. The matcher
(`nk_rtl::wildcard`) runs the expression as a state machine over the
name, a bit per expression character in a fixed four kilobytes of the
caller's stack: its time is bounded by the product of the two lengths
whatever the pattern, it allocates nothing, and so it never raises,
where Windows raises `STATUS_NO_MEMORY`. What matches is what Windows
matches, the two cases included that the documented wording of the DOS
wildcards does not cover (stated in `nk_rtl::wildcard`). The name is
upper-cased by the caller's table when one is passed, read from the
caller's memory a unit at a time. The table of legal characters is
built from each file system's naming rules (`nk_rtl::legal`) and is
Windows 10's entry for entry: Microsoft publishes the flags and the
macros that read the table, not its contents.

### The prefix table

A [prefix table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix)
and its entries are the driver's memory, with the fields `ntifs.h`
declares (`nk_ntabi::rtl`), and an entry points to the caller's name
without copying it. NK keeps nothing beside them: the routines link the
driver's entries through the driver's own fields, as the header's names
describe (a list of trees by number of name components, a search tree
in each, a ring of the names that differ only in case). The algorithm
is `nk_rtl::prefix`, written against a store of nodes: the kernel's
store is the driver's fields behind raw pointers, the host tests' is a
vector, checked against a plain list over random sequences. No routine
allocates, so none can fail for want of memory. Which rotations balance
a tree is NK's choice: a name found without regard to case is splayed
to its tree's root. The caller serialises the calls on one table, as on
Windows. `RtlNextUnicodePrefix` is not exported.

### Splay trees

`RtlSplay` and `RtlDelete` work on a tree of the caller's
`RTL_SPLAY_LINKS` (a file system's tree of names), which the caller
builds and searches itself with the header's macros. The algorithm is
`nk_rtl::splay`, written against a store of links like the prefix
table's and tested on the host. Which rotations a splay makes, and
which node a node with two children trades places with before it is
deleted (the one before it in order), are NK's choice: only the order
and the root returned are a caller's concern.

### The AVL table

An [AVL generic table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl)
is the driver's: its header (`RTL_AVL_TABLE`, `nk_ntabi::rtl`, checked
against the kernel's symbols), its order (the compare routine) and its
nodes, each an `RTL_BALANCED_LINKS` with the element copied after it in
a block from the allocate routine. The header's `BalancedRoot` is the
tree's sentinel, its own parent, with the root as its right child. The
balancing is `nk_rtl::avl`, written against a store of nodes as the
prefix table's is and checked on the host against a set over random
sequences. Insertion and deletion keep the element count, the delete
count and the depth the header declares, and forget its place of an
ordered walk. The caller serialises the calls on one table. The walks
(`RtlEnumerateGenericTableAvl` and its kin) are not exported: no binary
NK runs imports them.

### Bitmaps

An [`RTL_BITMAP`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap)
header and its buffer are the driver's memory, and NK keeps nothing
beside them. The rules are `nk_rtl::bitmap`, written against a buffer
read and written a byte or a `ULONG` at a time: the kernel's is the
driver's buffer behind a raw pointer, the host tests' a vector checked
against the same bits held one by one. A routine that changes a run
writes the bytes that hold the run and no others, as Windows does, so
two locks may guard two parts of one bitmap. What Microsoft's pages
leave open (where a search with a hint starts and wraps, what a search
stores when it finds nothing, how many bits a copy moves) is read from
the kernel NK follows and stated in `nk_rtl::bitmap`. The interlocked
routines change one `ULONG` at a time through an atomic.

### Resource descriptors

The encodings of a port or memory range's length in a
[resource descriptor](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor),
large memory included, are `nk_rtl::resource`; the exports in
`kernel/rtl` read and write a driver's descriptor field by field. The
layouts are `nk_ntabi::resource`, with the views of each union the
kernel itself uses.

### Range lists

A range list's header and its iterator are the driver's, laid out as
the Windows 2000 DDK declares them (`nk_ntabi::rtl`); the entries are
pool blocks of the kernel's, each beginning with the `RTL_RANGE` the
iterator hands out. Windows keeps overlapping ranges inside private
*merged* containers. NK keeps one chain in order of start and no
containers, which walks in the same order and gives every range the
same flags (`nk_rtl::range` says why), so an iterator's `MergedHead`
is always null. No routine but an add or a copy allocates, so deleting
cannot fail for want of memory as it can on Windows. `RtlAddRange`'s
flag 0x10, which no header declares and `acpi.sys` passes for its
interrupts, says the range's user data is a pool block starting with
a count of the entries that point to it: the range carries 0x10 in
its flags, a copy of the entry raises the count, an entry freed
lowers it and frees the block at zero, as the pinned kernel does. An
alignment of zero is refused by `RtlFindRange`; Windows divides by it.
The caller serialises the calls on one list.
