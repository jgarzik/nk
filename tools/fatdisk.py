"""A data disk holding a FAT32 volume, and the check of it after a boot.

The disk is a raw 64 MiB image with one partition, in an MBR or a GPT
(`LAYOUTS`), at sector 2048 and 126976 sectors long. The volume is
FAT32 with one sector a cluster, which gives it more clusters than FAT16
can count, and holds the files of `FILES`, written by mtools: a nested
one, an empty one and one with a long name among them. Every
identifier is fixed (the disk's signature or GUID, the partition's GUID,
the volume's serial), so a boot sees the same disk each time.

After the boot the image is checked with the host's tools: fsck.fat
finds the volume clean, and the files are what they were. Microsoft's
volume drivers find the partition and NK's tests read it, but nothing
writes it yet: "fat-unchanged" is the one check.

doc/TESTING.md states these numbers; the kernel's volume tests rely on
them.
"""

import os
import subprocess
import tempfile
from pathlib import Path

import datadisk

MIB = 64
START = 2048            # the partition's first sector
LENGTH = 126976         # its sectors: 62 MiB, clear of a GPT's backup
SIGNATURE = 0x4E4B0001  # the MBR's disk signature
DISK_GUID = "4E4B0000-0000-4000-8000-000000000001"
PARTITION_GUID = "4E4B0000-0000-4000-8000-000000000002"
BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
SERIAL = "4e4b0002"
LABEL = "NKVOL"

LAYOUTS = {
    "fat32-mbr": f"label: dos\nlabel-id: {SIGNATURE:#x}\nstart={START}, size={LENGTH}, type=c\n",
    "fat32-gpt": (f"label: gpt\nlabel-id: {DISK_GUID}\nstart={START}, size={LENGTH}, "
                  f"type={BASIC_DATA}, uuid={PARTITION_GUID}, name=\"NKDATA\"\n"),
}

# What a scenario's `disk_expect` may name for such a disk.
CHECKS = {"fat-unchanged", "fat-written", "fat-lazy"}


def pattern(length):
    """`length` bytes of the data disk's original pattern: a misplaced
    cluster of a file shows."""
    whole = (length + datadisk.SECTOR - 1) // datadisk.SECTOR
    return datadisk.sectors(0, whole, datadisk.ORIGINAL)[:length]


# The files of the volume: path (`/` between names) and contents.
FILES = {
    "HELLO.TXT": b"NK reads FAT\r\n",
    "PATTERN.BIN": pattern(3 * datadisk.SECTOR + 100),
    "DIR1/NESTED.TXT": b"nested\r\n",
    "Long File Name.txt": b"a name longer than 8.3\r\n",
    "EMPTY.TXT": b"",
}


# What the kernel's fat.write test leaves (kernel/selftest/fat.rs): a new
# file written from 192 KiB to 392 KiB over a hole of zeros, 1 KiB at
# 300 KiB written again with 0xEE, cut to 350 KiB; EMPTY.TXT renamed;
# HELLO.TXT deleted.
WRITE_FROM, WRITE_TO = 192 * 1024, 392 * 1024
OVERWRITE_AT, OVERWRITE = 300 * 1024, 1024
CUT_TO = 350 * 1024
# What fat.lazy leaves: a new file of the same pattern, never flushed.
LAZY_LENGTH = 100 * 1024


def written_file():
    """NKWRITE.BIN's bytes as fat.write leaves them."""
    data = bytearray(CUT_TO)
    for at in range(WRITE_FROM, CUT_TO):
        data[at] = (at * 7 + 3) % 251
    data[OVERWRITE_AT:OVERWRITE_AT + OVERWRITE] = b"\xee" * OVERWRITE
    return bytes(data)


def expected(expect):
    """The files the volume must hold after a boot checked as `expect`."""
    if expect == "fat-unchanged":
        return dict(FILES)
    if expect == "fat-lazy":
        files = dict(FILES)
        files["LAZY.BIN"] = bytes((at * 7 + 3) % 251 for at in range(LAZY_LENGTH))
        return files
    files = {name: data for name, data in FILES.items() if name not in ("HELLO.TXT", "EMPTY.TXT")}
    files["RENAMED.TXT"] = FILES["EMPTY.TXT"]
    files["NKWRITE.BIN"] = written_file()
    return files


def _mtools(*args, data=None):
    env = dict(os.environ, MTOOLS_SKIP_CHECK="1")
    return subprocess.run(args, input=data, capture_output=True, check=True, env=env).stdout


def _volume(path):
    return f"{path}@@{START * datadisk.SECTOR}"


def create(path, layout):
    """Write the image for `layout` (a key of LAYOUTS)."""
    with open(path, "wb") as f:
        f.truncate(MIB << 20)
    subprocess.run(["sfdisk", "-q", str(path)], input=LAYOUTS[layout].encode(),
                   capture_output=True, check=True)
    volume = _volume(path)
    _mtools("mformat", "-i", volume, "-F", "-c", "1", "-T", str(LENGTH), "-H", str(START),
            "-v", LABEL, "-N", SERIAL, "::")
    for name in sorted(FILES):
        parts = name.split("/")
        for depth in range(1, len(parts)):
            directory = "::" + "/".join(parts[:depth])
            if subprocess.run(["mdir", "-i", volume, directory], capture_output=True,
                              env=dict(os.environ, MTOOLS_SKIP_CHECK="1")).returncode != 0:
                _mtools("mmd", "-i", volume, directory)
        with tempfile.NamedTemporaryFile(dir=Path(path).parent) as f:
            f.write(FILES[name])
            f.flush()
            _mtools("mcopy", "-i", volume, f.name, "::" + name)


def verify(path, expect):
    """Compare the image with `expect` (a member of CHECKS). Returns the
    problems found; none means it passed."""
    assert expect in CHECKS
    problems = []
    with tempfile.TemporaryDirectory(dir=Path(path).parent) as scratch:
        part = Path(scratch) / "volume.img"
        with open(path, "rb") as src, open(part, "wb") as dst:
            src.seek(START * datadisk.SECTOR)
            dst.write(src.read(LENGTH * datadisk.SECTOR))
        fsck = subprocess.run(["fsck.fat", "-n", str(part)], capture_output=True, text=True)
        if fsck.returncode != 0:
            last = (fsck.stdout.strip().splitlines() or ["(no output)"])[-1]
            problems.append(f"FAT disk: fsck.fat finds the volume damaged: {last}")
            return problems
    volume = _volume(path)
    files = expected(expect)
    for name, want in sorted(files.items()):
        try:
            got = _mtools("mtype", "-i", volume, "::" + name)
        except subprocess.CalledProcessError:
            problems.append(f"FAT disk: {name} is gone")
            continue
        if got != want:
            problems.append(f"FAT disk: {name} holds other bytes than it was given")
    listing = _mtools("mdir", "-i", volume, "-b", "-/", "::").decode(errors="replace")
    names = {line.strip().removeprefix("::/").upper() for line in listing.splitlines()
             if line.strip() and not line.strip().endswith("/")}
    extra = names - {n.upper() for n in files}
    if extra:
        problems.append(f"FAT disk: files no one wrote: {', '.join(sorted(extra))}")
    return problems
