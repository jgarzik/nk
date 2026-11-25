#!/usr/bin/env python3
"""Build the EFI system partition image a boot needs: loader, kernel, drivers.

Layout, mirroring where Windows keeps its boot files:

    \\EFI\\BOOT\\BOOT{X64,AA64}.EFI   nkload (the path firmware boots by default)
    \\NK\\nkkrnl.exe                  the kernel
    \\NK\\drivers\\<name>.sys         boot drivers, from the fixture cache

The image is a bare FAT filesystem made with mtools: no root, no loop device.
"""

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
    """[(name on the ESP, path)] for fixtures the kernel loads on this arch.
    A fixture that is not downloaded is left out; the kernel reports it."""
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    drivers = []
    for fx in manifest:
        path = FIXTURES / fx["file"]
        if fx["arch"] == arch and fx.get("boot", True) and path.exists():
            drivers.append((fx["name"] + ".sys", path))
    return drivers


def build(arch, image, extra_drivers=()):
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
    for name, path in [*boot_drivers(arch), *extra_drivers]:
        mtools("mcopy", "-i", image, path, f"::/NK/drivers/{name}")
