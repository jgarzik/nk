#!/usr/bin/env python3
"""Build the EFI system partition image a boot needs: loader, kernel, drivers.

Layout, mirroring where Windows keeps its boot files:

    \\EFI\\BOOT\\BOOT{X64,AA64}.EFI   nkload (the path firmware boots by default)
    \\NK\\nkkrnl.exe                  the kernel
    \\NK\\drivers\\<name>.<ext>       boot files (drivers and the libraries
                                    they import from), from the fixture cache
    \\NK\\SYSTEM                      the SYSTEM registry hive, from the fixture cache
    \\NK\\cmdline.txt                 the kernel command line, if any

The image is a bare FAT filesystem made with mtools: no root, no loop device.

Usage: mkesp.py <x86_64|aarch64> <output.img> [--no-drivers]

`--no-drivers` leaves the fixture drivers and the hive out. Such an image contains only
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


def boot_name(fx):
    """The name a fixture image has on the boot volume, which is the name
    the kernel and the import tables of other images know it by: the
    fixture's `name` with the extension of its `file` (`null.x64.sys` is
    `null.sys`, `pshed.x64.dll` is `pshed.dll`)."""
    return fx["name"] + Path(fx["file"]).suffix


def boot_files(arch, manifest):
    """[(name on the ESP, fixture)] for the fixtures of `manifest` the
    kernel uses on this arch.

    Besides the images it loads, the kernel is given real binaries it
    must refuse:
      wrongarch.sys   the WDM sample built for the other architecture
      unresolved.sys  the KMDF sample, whose framework imports NK lacks
      nkc-libbad.sys  imports a name the library nkc-lib.sys does not export
    """
    files = []
    for fx in manifest:
        if "kind" in fx:  # a table or symbol file, not an image
            continue
        if fx["arch"] == arch and fx.get("boot", True):
            files.append((boot_name(fx), fx))
        elif fx["arch"] != arch and fx["name"] == "sioctl":
            files.append(("wrongarch.sys", fx))
        elif fx["arch"] == arch and fx["name"] == "kmdf-echo":
            files.append(("unresolved.sys", fx))
        elif fx["arch"] == arch and fx["name"] == "nkc-libbad":
            files.append(("nkc-libbad.sys", fx))
    return files


def boot_drivers(arch):
    """([(name on the ESP, path)], [missing file names]) for the fixtures
    the kernel uses on this arch. A fixture that is not downloaded is left
    out and named in the second list; the kernel skips its tests."""
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    # Any image that is absent is named, whichever arch it is for.
    missing = [fx["file"] for fx in manifest
               if "kind" not in fx and not (FIXTURES / fx["file"]).exists()]
    drivers = [(name, FIXTURES / fx["file"]) for name, fx in boot_files(arch, manifest)
               if (FIXTURES / fx["file"]).exists()]
    return drivers, missing


def hive():
    """(path, missing file name or None) of the registry hive fixture: the
    one fixture of kind "hive", the same for every architecture."""
    manifest = tomllib.loads((ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
    [fx] = [fx for fx in manifest if fx.get("kind") == "hive"]
    path = FIXTURES / fx["file"]
    return (path, None) if path.exists() else (None, fx["file"])


def build(arch, image, drivers=True, cmdline=""):
    """Write the ESP image for `arch` to `image`. Returns the names of the
    driver fixtures that should be on it but are not downloaded (or a
    marker when drivers were left out on purpose)."""
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
    found, missing = boot_drivers(arch) if drivers else ([], ["(no drivers)"])
    for name, path in found:
        mtools("mcopy", "-i", image, path, f"::/NK/drivers/{name}")
    if drivers:
        path, absent = hive()
        if path:
            mtools("mcopy", "-i", image, path, "::/NK/SYSTEM")
        else:
            missing.append(absent)
    if cmdline:
        text = image.with_suffix(".cmdline")
        text.write_text(cmdline + "\n")
        try:
            mtools("mcopy", "-i", image, text, "::/NK/cmdline.txt")
        finally:
            text.unlink()
    return missing


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2 or args[0] not in BOOT_NAME:
        sys.exit(__doc__)
    build(args[0], Path(args[1]), drivers="--no-drivers" not in sys.argv)
