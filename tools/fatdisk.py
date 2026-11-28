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
import struct
import subprocess
import tempfile
from pathlib import Path

import datadisk
import mkesp

MIB = 64
DUAL_MIB = 128
START = 2048            # the first partition's first sector
LENGTH = 126976         # its sectors: 62 MiB, clear of a GPT's backup
START2 = START + LENGTH # second partition's first sector (for two-partition disks)
LENGTH2 = 126976        # second partition's sectors: 62 MiB
SIGNATURE = 0x4E4B0001  # the MBR's disk signature
DISK_GUID = "4E4B0000-0000-4000-8000-000000000001"
PARTITION_GUID = "4E4B0000-0000-4000-8000-000000000002"
PARTITION2_GUID = "4E4B0000-0000-4000-8000-000000000003"
BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
SERIAL = "4e4b0002"
SERIAL2 = "4e4b0003"
LABEL = "NKVOL"
LABEL2 = "NKDATA2"

LAYOUTS = {
    "fat32-mbr": f"label: dos\nlabel-id: {SIGNATURE:#x}\nstart={START}, size={LENGTH}, type=c\n",
    "fat32-gpt": (f"label: gpt\nlabel-id: {DISK_GUID}\nstart={START}, size={LENGTH}, "
                  f"type={BASIC_DATA}, uuid={PARTITION_GUID}, name=\"NKDATA\"\n"),
    "fat32-sys-gpt": (f"label: gpt\nlabel-id: {DISK_GUID}\nstart={START}, size={LENGTH}, "
                      f"type={BASIC_DATA}, uuid={PARTITION_GUID}, name=\"NKSYS\"\n"),
    "fat32-autochk-dirty-gpt": (
        f"label: gpt\nlabel-id: {DISK_GUID}\n"
        f"start={START}, size={LENGTH}, type={BASIC_DATA}, uuid={PARTITION_GUID}, name=\"NKSYS\"\n"
        f"start={START2}, size={LENGTH2}, type={BASIC_DATA}, uuid={PARTITION2_GUID}, name=\"NKDATA2\"\n"
    ),
}

# What a scenario's `disk_expect` may name for such a disk.
CHECKS = {"fat-unchanged", "fat-written", "fat-lazy", "sys-clean", "autochk-dirty"}


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


def _volume(path, start=START):
    return f"{path}@@{start * datadisk.SECTOR}"


def _populate_files(path, volume, files):
    for name in sorted(files):
        parts = name.split("/")
        for depth in range(1, len(parts)):
            directory = "::" + "/".join(parts[:depth])
            if subprocess.run(["mdir", "-i", volume, directory], capture_output=True,
                              env=dict(os.environ, MTOOLS_SKIP_CHECK="1")).returncode != 0:
                _mtools("mmd", "-i", volume, directory)
        with tempfile.NamedTemporaryFile(dir=Path(path).parent) as f:
            f.write(files[name])
            f.flush()
            _mtools("mcopy", "-i", volume, f.name, "::" + name)


def _stage_system32(volume):
    """Stage Windows user-mode binaries (`ntdll.dll`, `autochk.exe`) and NK's
    in-tree native test binary (`nkt.exe`) into `\\Windows\\System32`."""
    for d in ("::Windows", "::Windows/System32"):
        _mtools("mmd", "-i", volume, d)
    for dst_name, src in (
        ("ntdll.dll", mkesp.user_fixture("ntdll")),
        ("autochk.exe", mkesp.user_fixture("autochk")),
        ("nkt.exe", mkesp.ROOT / "target" / "x86_64-unknown-uefi" / "release" / "nkt.efi"),
    ):
        if src is not None and src.exists():
            _mtools("mcopy", "-i", volume, str(src), f"::Windows/System32/{dst_name}")


def corrupt_fat32_partition(path, start=START2):
    """Deliberately corrupt a FAT32 partition in-place: clear the clean-shutdown
    bit (bit 27 of FAT[1]) and link a 2-cluster orphan chain in both FAT copies
    with no directory entry referencing it, so `fsck.fat -n` reports damage and
    `autochk.exe` must repair it."""
    base = start * datadisk.SECTOR
    with open(path, "r+b") as f:
        f.seek(base)
        bpb = f.read(512)
        bytes_per_sector = struct.unpack_from("<H", bpb, 11)[0]
        reserved = struct.unpack_from("<H", bpb, 14)[0]
        num_fats = bpb[16]
        fat_sectors = struct.unpack_from("<I", bpb, 36)[0]
        fat_bytes = fat_sectors * bytes_per_sector

        # Read FAT 0, clear ClnShutBitMask (0x0800_0000) in entry 1, and find
        # two free clusters to link into an orphaned chain.
        fat0_off = base + reserved * bytes_per_sector
        f.seek(fat0_off)
        fat = bytearray(f.read(fat_bytes))

        entry1 = struct.unpack_from("<I", fat, 4)[0]
        struct.pack_into("<I", fat, 4, entry1 & ~0x0800_0000)

        free = []
        for clus in range(16, min(len(fat) // 4, 4096)):
            val = struct.unpack_from("<I", fat, clus * 4)[0] & 0x0FFF_FFFF
            if val == 0:
                free.append(clus)
                if len(free) == 2:
                    break
        assert len(free) == 2, "FAT32 volume has fewer than 2 free clusters"
        c0, c1 = free
        struct.pack_into("<I", fat, c0 * 4, c1)
        struct.pack_into("<I", fat, c1 * 4, 0x0FFF_FFFF)

        for fat_idx in range(num_fats):
            f.seek(base + (reserved + fat_idx * fat_sectors) * bytes_per_sector)
            f.write(fat)


def create(path, layout):
    """Write the image for `layout` (a key of LAYOUTS)."""
    dual = layout == "fat32-autochk-dirty-gpt"
    size_mib = DUAL_MIB if dual else MIB
    with open(path, "wb") as f:
        f.truncate(size_mib << 20)
    subprocess.run(["sfdisk", "-q", str(path)], input=LAYOUTS[layout].encode(),
                   capture_output=True, check=True)
    volume = _volume(path, START)
    _mtools("mformat", "-i", volume, "-F", "-c", "1", "-T", str(LENGTH), "-H", str(START),
            "-v", LABEL, "-N", SERIAL, "::")
    _populate_files(path, volume, FILES)
    if layout in ("fat32-sys-gpt", "fat32-autochk-dirty-gpt"):
        _stage_system32(volume)
    if dual:
        vol2 = _volume(path, START2)
        _mtools("mformat", "-i", vol2, "-F", "-c", "1", "-T", str(LENGTH2), "-H", str(START2),
                "-v", LABEL2, "-N", SERIAL2, "::")
        _populate_files(path, vol2, {"DATA.TXT": b"second FAT32 volume\r\n"})
        corrupt_fat32_partition(path, START2)


def _fsck_partition(path, start, length, label):
    with tempfile.TemporaryDirectory(dir=Path(path).parent) as scratch:
        part = Path(scratch) / "volume.img"
        with open(path, "rb") as src, open(part, "wb") as dst:
            src.seek(start * datadisk.SECTOR)
            dst.write(src.read(length * datadisk.SECTOR))
        fsck = subprocess.run(["fsck.fat", "-n", str(part)], capture_output=True, text=True)
        if fsck.returncode != 0:
            last = (fsck.stdout.strip().splitlines() or ["(no output)"])[-1]
            return f"FAT disk ({label}): fsck.fat finds the volume damaged: {last}"
    return None


def verify(path, expect):
    """Compare the image with `expect` (a member of CHECKS). Returns the
    problems found; none means it passed."""
    assert expect in CHECKS
    problems = []
    err = _fsck_partition(path, START, LENGTH, "part1")
    if err:
        problems.append(err)
        return problems
    if expect == "sys-clean":
        return problems
    if expect == "autochk-dirty":
        err2 = _fsck_partition(path, START2, LENGTH2, "part2")
        if err2:
            problems.append(err2)
            return problems
        # Check that autochk.exe wrote a non-empty BOOTEX.LOG on partition 2 (or 1).
        bootex = b""
        for start in (START2, START):
            try:
                bootex = _mtools("mtype", "-i", _volume(path, start), "::BOOTEX.LOG")
                if bootex:
                    break
            except subprocess.CalledProcessError:
                continue
        if not bootex:
            problems.append("FAT disk: BOOTEX.LOG is absent or empty after autochk repair")
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
