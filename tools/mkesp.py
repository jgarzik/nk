#!/usr/bin/env python3
"""Build the EFI system partition image a boot needs: loader, kernel, drivers.

Layout, mirroring where Windows keeps its boot files:

    \\EFI\\BOOT\\BOOT{X64,AA64}.EFI   nkload (the path firmware boots by default)
    \\NK\\nkkrnl.exe                  the kernel
    \\NK\\drivers\\<name>.sys         boot drivers, from the fixture cache

The image is a bare FAT filesystem made with mtools: no root, no loop device.

Usage: mkesp.py <x86_64|aarch64> <output.img> [--no-drivers]

`--no-drivers` leaves the fixture drivers out. Such an image contains only
NK's own code and can be redistributed; the kernel boots and reports the
driver tests as skipped.
"""

import sys

import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "target" / "fixtures"
SIZE_MB = 64
BOOT_NAME = {"x86_64": "BOOTX64.EFI", "aarch64": "BOOTAA64.EFI"}


def binaries(arch):
    out = ROOT / "target" / f"{arch}-unknown-uefi" / "release"
    return out / "nkload.efi", out / "nkkrnl.efi"


def boot_drivers(arch):
    """[(name on the ESP, path)] for the fixtures the kernel uses on this arch.
    A fixture that is not downloaded is left out; the kernel reports it.

    Besides the drivers it loads, the kernel is given two real binaries it
    must refuse:
      wrongarch.sys   the WDM sample built for the other architecture
      unresolved.sys  the KMDF sample, whose framework imports NK lacks
    """
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    drivers = []
    for fx in manifest:
        path = FIXTURES / fx["file"]
        if not path.exists():
            continue
        if fx["arch"] == arch and fx.get("boot", True):
            drivers.append((fx["name"] + ".sys", path))
        elif fx["arch"] != arch and fx["name"] == "sioctl":
            drivers.append(("wrongarch.sys", path))
        elif fx["arch"] == arch and fx["name"] == "kmdf-echo":
            drivers.append(("unresolved.sys", path))
    return drivers


def build(arch, image, drivers=True):
    """Write the ESP image for `arch` to `image`."""
    loader, kernel = binaries(arch)
    for f in (loader, kernel):
        if not f.exists():
            raise SystemExit(f"mkesp: {f} not built (run: make build / build-arm)")
    image.parent.mkdir(parents=True, exist_ok=True)
    image.unlink(missing_ok=True)
    with open(image, "wb") as f:
        f.truncate(SIZE_MB << 20)

    def mtools(*args):
        subprocess.run(args, check=True, capture_output=True)

    mtools("mformat", "-i", image, "-F", "::")
    for d in ("EFI", "EFI/BOOT", "NK", "NK/drivers"):
        mtools("mmd", "-i", image, f"::/{d}")
    mtools("mcopy", "-i", image, loader, f"::/EFI/BOOT/{BOOT_NAME[arch]}")
    mtools("mcopy", "-i", image, kernel, "::/NK/nkkrnl.exe")
    for name, path in boot_drivers(arch) if drivers else []:
        mtools("mcopy", "-i", image, path, f"::/NK/drivers/{name}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2 or args[0] not in BOOT_NAME:
        sys.exit(__doc__)
    build(args[0], Path(args[1]), drivers="--no-drivers" not in sys.argv)
