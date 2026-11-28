# Security

Part of NK's design ([DESIGN.md](../DESIGN.md)): the principles there apply.

## Security descriptors

SIDs, ACLs and descriptors are byte layouts with rules: `lib/se`, with
the exports in `kernel/se`. A driver's descriptor is the driver's memory:
read and written through raw pointers, the rules run on copies.
`SeExports` points to the well-known SIDs and privilege numbers, laid out
as in `ntifs.h`.

A SID's first two bytes say whether it is one and how long it is, so
the routines that take one read those before the rest and never read a
SID by a length it does not have; they copy at most the 68 bytes of the
largest SID, onto the stack. `RtlValidSecurityDescriptor` judges an
access list on a pool copy and answers "not valid" without memory for
one. App-container SIDs (`RtlGetAppContainerSidType`,
`RtlGetAppContainerParent`) are told apart by shape alone, `S-1-15-2`
with eight or twelve sub-authorities, and refused with Windows'
statuses (`nk_se::sid`); a parent's SID is a pool block the caller
frees.

Kernel-mode opens bypass security checks unless `OBJ_FORCE_ACCESS_CHECK`
is set, as on Windows; user-mode opens check access against the object's
security descriptor through `ob::check_access` -> `SeAccessCheck`. A
driver that guards its own objects asks
[`SeAccessCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seaccesscheck)
and gets Windows' answer (below). Descriptors are
built, converted, captured and stored faithfully. `ZwSetSecurityObject`
and `ObSetSecurityObjectByPointer` (by handle and by pointer) replace
the named parts of a device's descriptor; for other objects they answer
`STATUS_NOT_SUPPORTED`. Every new device gets Windows' default security
descriptor (`se::default_device_sd`: Owner/Group `SYSTEM`, DACL granting
`SYSTEM` and `Administrators` `GENERIC_ALL` and `World`
`GENERIC_READ | GENERIC_EXECUTE`). `SeCaptureSecurityDescriptor`,
forced, returns a self-relative pool copy, the caller's to free.

A driver that keeps descriptors for its own objects (a file system)
gets them from
[`SeAssignSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurity)
(the rules: `lib/se/assign.rs`), reads parts of one with
`SeQuerySecurityDescriptorInfo` and changes one with
`SeSetSecurityDescriptorInfo` (`lib/se/descriptor.rs`). Each descriptor
handed out is one self-relative pool block, the driver's to keep and
free, laid out lists first, then owner and group; what a query copies
out is laid out owner, group, DACL, SACL, as Windows' is; a changed descriptor is a new block and the old one is the
driver's to free. A list the creator supplies, or the token's default,
is assigned whole, as long as it says it is, its generic rights mapped
and the masks kept within what "generic all" maps to; the
creator-owner and creator-group SIDs are replaced by the new owner and
group only in entries inherited from the parent. Every creator is a kernel-mode creator, which may
name any owner for a new object; changing an owner asks the caller's
token, as on Windows. A changed descriptor always has an owner and a
group: naming one and supplying none is refused
(`STATUS_INVALID_OWNER`, `STATUS_INVALID_PRIMARY_GROUP`), where naming
the DACL and supplying none leaves the object a null DACL, which
allows everyone everything: Windows' rules, a caller's to know.

Where a descriptor lives:

- A device's is in `DEVICE_OBJECT.SecurityDescriptor`, a documented
  field a driver can read, as on Windows: a pool block the device owns,
  replaced under the I/O database lock.
- Any other object can carry one in `OBJECT_HEADER.SecurityDescriptor`
  (`kernel/ob/security.rs`): a reference to a copy in the store below,
  set, referenced and released by kernel routines, given up with the
  object or when replaced. The field is Windows' fast reference with
  its count bits zero. No object type gives its objects a descriptor:
  NK has no types' security procedures.
- The store (`nk_ob::descriptors`) keeps one counted, self-relative
  copy of each distinct descriptor, as Windows' does: logging the same
  bytes again, from whatever address, returns the same copy with more
  references, and the copy is freed with its last. A file system logs
  its files' descriptors there (`ObLogSecurityDescriptor`) and holds
  the copies (`ObReferenceSecurityDescriptor`,
  `ObDereferenceSecurityDescriptor`); objects with equal descriptors
  share a copy. What precedes a copy in its block (its count, a hash of
  its bytes) is NK's own. Giving up more references than are held stops
  the system, as Windows' fast fail does (`0x139`).

A descriptor can also come as an SDDL string (`nk_se::sddl`), which
`IoCreateDeviceSecure` takes for the device it makes
([I/O](io.md)): an owner, a group and a DACL, with the ACE types,
flags, rights and SID names `nk_se::sddl` lists, and SIDs written out
in full. SDDL beyond that stops the system naming what was not
understood; a string that is not SDDL is refused.

`RtlDeriveCapabilitySidsFromName` gives the two SIDs of a capability
(`nk_se::capability`): the SHA-256 hash of its name in capitals, as
`S-1-5-32-...` for its group and `S-1-15-3-1024-...` for itself, the
twelve capabilities of the first Windows 8 applications keeping their
`S-1-15-3-n`. A missing buffer is a fast fail (`0x139`), as on
Windows.

## Tokens and access state

A token is an object whose body is NK's own (`nk_se::token::Token`):
drivers treat `TOKEN` as opaque and ask through routines. There is one
logon, the system's: the System process's token has the user, groups
and privileges of Windows' SYSTEM token (the table at `Token::system`
says which of those facts Microsoft documents), and every other token
is a copy of it, but one. That one is the anonymous logon's
(`Token::anonymous`, S-1-5-7), made at boot as Windows makes it, which
a thread takes on to act as nobody (`ZwImpersonateAnonymousToken`):
it is in no group, not even everyone, and holds no privilege. Its
integrity level is "untrusted", by which Windows would also deny it
write access to objects that carry no label; NK applies no mandatory
policy.

A thread may impersonate: act with another token than its process's.
It keeps that token where Windows does, since Microsoft's drivers are
built against the thread's layout: `ETHREAD.ClientSecurity` holds the
token's address, the impersonation level and "effective only", and two
bits of `CrossThreadFlags` say that it impersonates and that opening
its token copies it (`kernel/se/impersonate.rs`). The thread holds a
reference to the token until it puts it off or is freed. A thread
takes a token on through `ZwSetInformationThread`
(`ThreadImpersonationToken`: an impersonation token by handle, or
none), and anyone may ask what a thread wears
(`PsReferenceImpersonationToken`, `ZwOpenThreadTokenEx`). A server
records its client in a `SECURITY_CLIENT_CONTEXT` of its own
([`SeCreateClientSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-secreateclientsecurity):
the client's token itself when tracked dynamically, a copy at the
level asked when tracked statically) and later takes it on
(`SeImpersonateClientEx`). Windows
lowers the level of an impersonation its process is not entitled to;
the System process, the only one, is entitled to all.

A driver asks a token about itself with
[`SeQueryInformationToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequeryinformationtoken)
(`lib/se/information.rs` lists the classes answered; the others fail
with `STATUS_INVALID_INFO_CLASS`) and `SeTokenType`. An answer with
parts of variable length is a pool block the driver frees; the session
id, the integrity level and "is an app container" are numbers written
in place of the block's address, as on Windows.

By handle a driver opens the process's token (`ZwOpenProcessTokenEx`),
asks it the same questions into a buffer of its own
(`ZwQueryInformationToken`) and copies it (`ZwDuplicateToken`). A copy
is a new token object: the same user, groups, privileges and defaults,
of the type asked, at the impersonation level its quality of service
names or else the source's own, with ids of its own. Every token's
statistics report Windows' least charge for its dynamic part, 0x1000
bytes, and none of it available, as Windows' do. An effective-only
copy leaves out the privileges and groups not in effect
(`Token::duplicate`).

A token never changes once it is made: NK exports nothing that adjusts
one. So a token has no lock, and
[`SeLockSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-selocksubjectcontext)
is what is left of Windows' routine when the token lock cannot be
contended: a critical region for each token of the subject.

What an open carries about its requestor has Windows' layout, because a
file system reads it in line (`kernel/se/token.rs`):

- the subject context
  ([`SeCaptureSubjectContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-secapturesubjectcontext)):
  the token the thread impersonates and at which level, the primary
  token (both referenced until the context is released), the process
  id for auditing. With no client token the impersonation level is not
  written, as on Windows;
- the access state (`SeCreateAccessState`), in the two structures its
  maker supplies, `ACCESS_STATE` and `AUX_ACCESS_DATA`: the subject, an
  operation id of its own, the access asked for as both original and
  remaining (generic rights mapped when a mapping is given), nothing
  granted yet, the traverse flag when the token holds
  `SeChangeNotifyPrivilege` enabled, and the privileges used, which
  start in the state's own set. An open NK makes itself gets both
  structures, with the file type's mapping. `SeDeleteAccessState` frees
  what the state came to own in the pool and releases the subject.

`SeAccessCheck` decides by the descriptor's DACL and owner and by the
subject's token: the client token of the captured subject if it has
one, else the primary token. The rules, their order and their statuses
are those of the pinned kernel's code (`lib/se/access.rs` lists them);
what that code does beyond them (mandatory integrity labels, restricted
tokens, object-specific and conditional entries, AppContainers) is not
done. Generic rights are the caller's to map, as on Windows. A right
that a privilege granted comes back in a privilege set from the pool,
which `SeFreePrivileges` frees.

Nothing audits: NK has no audit policy and nobody to report to, which
is Windows with every audit category off. `SeOpenObjectAuditAlarm`
does what Windows' does then (`kernel/se/audit.rs`): it clears the
access state's "generate audit" mark and leaves the caller's
"generate on close" as it was.

The privilege checks (`SePrivilegeCheck`, `SeSinglePrivilegeCheck`)
answer for the same subject, and mark in the caller's set the
privileges found enabled (`lib/se/privilege.rs`). A kernel-mode caller
holds every privilege, unmarked. `SeAppendPrivileges` records the
privileges an open used in its access state: in the state's own set
while three are enough, in a pool block after.
