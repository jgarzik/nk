# The Windows oracle

Each `<name>.script` here is replayed twice: on real Windows, by
`runner.ps1` inside the reference VM (`tools/oracle.py`), and on NK, by
the kernel self-test `oracle.<name>` (`kernel/selftest/oracle.rs`). Both
print a transcript, one line per step. `<name>.txt` is the transcript
Windows produced; the kernel test fails at the first line where NK's
differs.

`make oracle` re-records every transcript on Windows and fails if one no
longer matches its file. It needs KVM and the reference VM, so it is not
part of the gate; the gate runs the NK side against the committed files.
A transcript records the SHA-256 of its script and of every file it was
made with (the drivers of its `load` steps and the libraries of its
`install` steps), and a unit test fails when one has changed since.

There is one runner and one grammar: when `runner.ps1` changes, every
transcript is recorded again with it.

Windows here is Windows 10 Enterprise 22H2, build 19045.2006, x86-64.
The transcripts do not depend on the architecture, so arm64 NK is held to
the same lines.

## Script

One step per line; `#` starts a comment. Fields are separated by spaces.

| Step | Meaning |
| --- | --- |
| `debugger` | first step of a script for a system with a kernel debugger attached that says "go" at every breakpoint; reports `attached` or `absent` |
| `load <service> <file>` | load the test driver `<file>` as `<service>` |
| `install <file>` | put the library `<file>` in `System32\drivers`, where a driver loaded afterwards finds what it imports from; a file of that name already there is not replaced; removed when the script ends |
| `use <service>` | a driver that is part of the system: started if it is stopped, and stopped when the script ends only if this step started it |
| `open <handle> <path> [option...]` | open an object-manager path, for synchronous I/O unless the options say otherwise |
| `pipe <handle> <path> [option...]` | create an instance of the named pipe `<path>` (`NtCreateNamedPipeFile`): its server end |
| `ioctl <handle> <code> <input> <length>` | device control: code in hex, input bytes in hex or `-` for none, output buffer of `<length>` bytes |
| `ioctlat <handle> <code> <input> <output>` | device control where either buffer may be at an address the script chooses: `<input>` as for `ioctl` or `@<address>:<length>`, `<output>` a length as for `ioctl` or `@<address>:<length>` |
| `fsctl <handle> <code> <input> <length>` | file-system control (`NtFsControlFile`), fields as for `ioctl` |
| `read <handle> <length>` | read into a buffer of `<length>` bytes |
| `write <handle> <data>` | write the bytes given in hex, or `-` for none |
| `close <handle>` | close |
| `unload <service>` | stop and remove a driver loaded by `load` |

Every output buffer the replayer provides starts filled with `0xEE`, so
bytes the driver or the I/O manager did not write are visible.

A service `use` started is stopped after the last step; one that was
running is left running. Windows cannot stop some drivers once they run
(a file system, for one): those stay. On NK a service with no key in the
registry is given one that names `<service>.sys` among the boot files.

NK's replayer does not carry out `install`: its line for such a step
says so, and the comparison fails there.

### Options

`open` and `pipe` end with any number of `<key>=<value>` fields, in any
order. Masks are in hex, counts in decimal.

| Option | Of | Default | Meaning |
| --- | --- | --- | --- |
| `root=<handle>` | `open` | none | `<path>` is relative to this open handle (`OBJECT_ATTRIBUTES.RootDirectory`) |
| `access=<mask>` | both | `c0100000` | desired access; the default is `GENERIC_READ \| GENERIC_WRITE \| SYNCHRONIZE` |
| `share=<mask>` | both | `open` `0`, `pipe` `3` | share access; `3` is read and write |
| `options=<mask>` | both | `open` `60`, `pipe` `20` | create options; `20` is `FILE_SYNCHRONOUS_IO_NONALERT`, `40` is `FILE_NON_DIRECTORY_FILE` |
| `disposition=<n>` | `pipe` | `3` | create disposition; `3` is `FILE_OPEN_IF`, `2` is `FILE_CREATE` |
| `type=<n>` | `pipe` | `0` | `0` a stream of bytes, `1` messages |
| `read=<n>` | `pipe` | `0` | the server end reads `0` bytes, `1` messages |
| `completion=<n>` | `pipe` | `0` | `0` a request waits, `1` it does not |
| `instances=<n>` | `pipe` | `1` | most instances of the pipe; `4294967295` is no limit |
| `inquota=<n>`, `outquota=<n>` | `pipe` | `4096` | bytes of buffer in each direction |
| `timeout=<n>` | `pipe` | `50` | default timeout in milliseconds |

`open` always opens what exists (`FILE_OPEN`); with no options it is the
request the defaults describe.

Every handle is synchronous unless a script's options make it otherwise,
and the replayer makes one request at a time: a `read` of a pipe with
nothing in it, or a listen (`fsctl`) with no client, never returns.

### Buffers at an address

`@<address>:<length>` in `ioctlat` passes the request that pointer and
that length as they are: the address in hex, the length in decimal. It
is for `METHOD_NEITHER`, where the driver is handed the caller's
pointers, and for what the I/O manager does with a pointer it cannot
use: `@0:16` is a null pointer, `@1000:16` is in the lowest 64 KiB,
which Windows never maps, and `@ffff800000000000:16` is in the kernel's
half of the address space on both architectures. A buffer written as for
`ioctl` is the replayer's own memory, so one request can pair a good
buffer with a bad one.

## With a debugger

A driver that executes a breakpoint stops a normally booted Windows
(bugcheck `0x7E`); with kernel debugging enabled Windows instead waits
for its debugger. A script that begins with `debugger` is replayed on
Windows booted with debugging enabled over the serial port, and
`tools/kd.py` is the debugger at the other end: it speaks just enough of
the kernel-debugger serial protocol to acknowledge what the kernel
reports, answer that it has no file to put in a driver's place, step
over a hard-coded breakpoint, and continue. On NK the same script needs
`debug=on` on the command line, which stands for that debugger.

Microsoft's event sample is replayed both ways: `event.script` without
a debugger (loading it stops the system), `event-debug.script` with one
(it runs).

## Transcript

Each step's line repeats the step, then `: `, then the result:

- `load`, `install`, `use`, `unload`: `ok` or `failed`. `use` says `ok`
  whether the service was running or had to be started.
- `open`, `close`: the status, eight hex digits.
- `pipe`: the status and `IoStatusBlock.Information`, the result of the
  create (`2`, `FILE_CREATED`, for a new pipe).
- `ioctl`, `fsctl`, `read`: status, byte count, and the whole output
  buffer in hex (`-` if it is empty).
- `ioctlat`: the same; an output buffer at an address is not the
  replayer's to show, and is `-`.
- `write`: status and byte count.

The step is repeated with its fields single-spaced and its options as
the script wrote them; `load` leaves out the file. The byte count, or a `pipe`'s
`Information`, is `-` when the status is an error (`0xC0000000` and up):
Windows does not report one for a failed request. The last line is `end`.

A step may stop Windows instead (a bugcheck). Then its line is the
transcript's last, with no `end` after it:

    load event: stopped 0000007e 80000003

`stopped`, the bugcheck code, and the bugcheck's first parameter, eight
hex digits each. The runner writes a record of its steps through to disk
as it goes, in a file that already has its full size, so the record
survives; the code and parameter come from Windows itself, by way of the
hypervisor. On NK such a script is run in a boot of its own
(`tools/scenarios.toml`), which must end in the same bugcheck at the
same step.

On Windows the requests are made with the native API (`NtCreateFile`,
`NtCreateNamedPipeFile`, `NtDeviceIoControlFile`, `NtFsControlFile`,
...), so the status is the one the I/O manager
returned, not a Win32 error code translated from it. The runner is a
user-mode program. On NK each request is likewise a system service made
on behalf of user mode, and the replayer's buffers are pages of the
user range.
