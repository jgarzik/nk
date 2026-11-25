# The Windows oracle

Each `<name>.script` here is replayed twice: on real Windows, by
`runner.ps1` inside the reference VM (`tools/oracle.py`), and on NK, by
the kernel self-test `oracle.<name>` (`kernel/selftest/oracle.rs`). Both
print a transcript, one line per step. `<name>.txt` is the transcript
Windows produced; the kernel test fails at the first line where NK's
differs. That is what "the driver cannot tell NK from Windows" means, one
request at a time.

`make oracle` re-records every transcript on Windows and fails if one no
longer matches its file. It needs KVM and the reference VM, so it is not
part of the gate; the gate runs the NK side against the committed files.
A transcript records the SHA-256 of its script and of the driver it was
made with, and a unit test fails when either has changed since.

Windows here is Windows 10 Enterprise 22H2, build 19045.2006, x86-64.
The transcripts do not depend on the architecture, so arm64 NK is held to
the same lines.

## Script

One step per line; `#` starts a comment. Fields are separated by spaces.

| Step | Meaning |
| --- | --- |
| `debugger` | first step of a script for a system with a kernel debugger attached that says "go" at every breakpoint; reports `attached` or `absent` |
| `load <service> <file>` | load the test driver `<file>` as `<service>` |
| `use <service>` | a driver that is part of Windows: already running there; NK loads `<service>.sys` |
| `open <handle> <path>` | open an object-manager path for synchronous I/O |
| `ioctl <handle> <code> <input> <length>` | device control: code in hex, input bytes in hex or `-` for none, output buffer of `<length>` bytes |
| `read <handle> <length>` | read into a buffer of `<length>` bytes |
| `write <handle> <data>` | write the bytes given in hex, or `-` for none |
| `close <handle>` | close |
| `unload <service>` | stop and remove a driver loaded by `load` |

Every output buffer starts filled with `0xEE`, so bytes the driver or
the I/O manager did not write are visible.

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

- `load`, `use`, `unload`: `ok` or `failed`.
- `open`, `close`: the status, eight hex digits.
- `ioctl`, `read`: status, byte count, and the whole output buffer in hex
  (`-` if it is empty).
- `write`: status and byte count.

The byte count is `-` when the status is an error (`0xC0000000` and up):
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
`NtDeviceIoControlFile`, ...), so the status is the one the I/O manager
returned, not a Win32 error code translated from it.
