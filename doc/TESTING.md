# Testing

Windows defines the expected behaviour. Until a Windows reference VM
exists, expectations come from Microsoft's documentation and from reading
the fixture binaries, and the ledger says so.

## Host unit tests

`make test`. Pure functions in `lib/` crates, tested on the build host.
Tests build their inputs in code (for example, synthetic PE images) so
they need no downloaded files. Tests that do use a fetched fixture report
that they were skipped when it is absent.

## Boot tests

`make check` (x86-64) and `make check-arm` (arm64) boot the real loader
and kernel under QEMU with UEFI firmware, the way a PC boots, and judge
the serial log. x86-64 uses KVM when available; arm64 is emulated.

The kernel reports each self-test on the serial console:

```
NK-TEST <name>:OK
NK-TEST <name>:FAIL <why>
NK-TEST <name>:SKIP <why>
NK-TEST-COMPLETE pass=<n> fail=<n> skip=<n>
```

A boot passes only if the totals line shows `fail=0`, no line reports a
failure, panic or bugcheck, and the kernel powered the machine off within
the timeout. Skips are printed, never counted as passes.

`tools/boot_test.py` owns the run: it builds the EFI system partition
image, copies the firmware variable store, starts QEMU in its own process
group, and on every exit path kills QEMU and deletes the image and the
copy. What remains is `target/qemu/serial-<arch>.log`.

Knobs: `BOOT_TEST_TIMEOUT` (seconds, default 120), `QEMU_SMP`, `QEMU_MEM`,
`NO_KVM=1`. `make run` / `make run-arm` boot with the console attached.

## Driver fixtures

`fixtures/manifest.toml` lists every Windows binary the tests use, with
its URL and SHA-256; `make fixtures` downloads them to `target/fixtures/`.
None is committed. The boot tests put them on the EFI system partition:

| File on the ESP | What it is | Expected |
| --- | --- | --- |
| `null.sys` | Microsoft's inbox Null driver | loads; read gives end-of-file, write accepts all bytes; unloads without leaks |
| `sioctl.sys` | Microsoft's WDM IOCTL sample, WDK-built | loaded from the next phase on |
| `wrongarch.sys` | the same sample built for the other architecture | refused: wrong machine |
| `unresolved.sys` | Microsoft's KMDF echo sample | refused: unresolved import, named in the log |

A fixture that is not present makes its tests print SKIP. There is no
Windows 10 arm64 `null.sys` fixture yet, so those tests skip on arm64.

Expected results come from Microsoft's documentation and from reading the
driver binaries. They have not been compared with a run on Windows.

Each driver test compares pool usage, free frames and namespace entries
before loading the driver and after unloading it.

## The gate

`make gate` runs every check a commit must pass and prints `GATE-OK`.
Each commit passes it alone, so history is bisectable.
