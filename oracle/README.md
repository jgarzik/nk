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

## Transcript

Each step's line repeats the step, then `: `, then the result:

- `load`, `use`, `unload`: `ok` or `failed`.
- `open`, `close`: the status, eight hex digits.
- `ioctl`, `read`: status, byte count, and the whole output buffer in hex
  (`-` if it is empty).
- `write`: status and byte count.

The byte count is `-` when the status is an error (`0xC0000000` and up):
Windows does not report one for a failed request. The last line is `end`.

On Windows the requests are made with the native API (`NtCreateFile`,
`NtDeviceIoControlFile`, ...), so the status is the one the I/O manager
returned, not a Win32 error code translated from it.
