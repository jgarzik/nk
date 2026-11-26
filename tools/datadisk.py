"""The data disk a boot scenario can attach, and the check of its bytes
after the boot.

The disk is a raw image. Seen as 64-bit little-endian words, word `k` of
the disk (the 8 bytes at byte offset 8 * k) holds

    seed ^ k

so sector `n` holds words 64 * n to 64 * n + 63, no two sectors are alike,
and a transfer that lands in the wrong place, even inside a sector, shows.
Before the boot every word has the seed ORIGINAL. A kernel test that writes
the disk writes the sectors [WRITE_FIRST, WRITE_END), and only those, with
the seed WRITTEN: the same function of the same `k`, so a sector written to
the wrong address shows too.

These numbers are the kernel test's as well: doc/TESTING.md states them,
and a change here is a change there.
"""

import array
import sys

SECTOR = 512
WORDS = SECTOR // 8  # per sector
DEFAULT_MIB = 64

ORIGINAL = 0x4E4B_4F52_0000_0000  # "NKOR" in the high half
WRITTEN = 0x4E4B_5752_0000_0000   # "NKWR"
# The sectors a kernel test may write: 128 KiB, 1 MiB into the disk.
WRITE_FIRST = 2048
WRITE_END = 2304

# What a scenario's `disk_expect` may name: whether the sectors of the
# write range hold the written pattern. Every other sector always has to
# hold the original one.
CHECKS = {"unchanged": False, "written": True}

# Sectors generated, and compared, at a time: 1 MiB.
_CHUNK = 2048
# How many wrong sectors are named before the rest are only counted.
_NAMED = 4


def sectors(first, count, seed):
    """The bytes of `count` sectors starting at sector `first`."""
    words = array.array("Q", (seed ^ k for k in range(first * WORDS, (first + count) * WORDS)))
    if sys.byteorder != "little":
        words.byteswap()
    return words.tobytes()


def seed_of(sector, written):
    """The seed sector number `sector` should have after a boot; `written`
    says whether the kernel was to write the write range."""
    return WRITTEN if written and WRITE_FIRST <= sector < WRITE_END else ORIGINAL


def create(path, mib=DEFAULT_MIB):
    """Write the image: `mib` MiB, every sector with the original pattern."""
    with open(path, "wb") as f:
        for first in range(0, (mib << 20) // SECTOR, _CHUNK):
            f.write(sectors(first, _CHUNK, ORIGINAL))


def _describe(got, sector):
    """What a sector that is not as expected holds instead."""
    for seed, name in ((ORIGINAL, "the original pattern"), (WRITTEN, "the written pattern")):
        if got == sectors(sector, 1, seed):
            return name
    if got == bytes(SECTOR):
        return "zeroes"
    return "neither pattern (starts " + got[:8].hex() + ")"


def verify(path, expect, mib=DEFAULT_MIB):
    """Compare the image with what the check named `expect` (a key of
    CHECKS) allows. Returns the problems found; none means it passed."""
    written = CHECKS[expect]
    total = (mib << 20) // SECTOR
    wrong = []
    with open(path, "rb") as f:
        for first in range(0, total, _CHUNK):
            got = f.read(_CHUNK * SECTOR)
            want = b"".join(
                sectors(start, end - start, seed_of(start, written))
                for start, end in _runs(first, first + _CHUNK, written))
            if got == want:
                continue
            for i in range(len(want) // SECTOR):
                piece = got[i * SECTOR:(i + 1) * SECTOR]
                if piece != want[i * SECTOR:(i + 1) * SECTOR]:
                    wrong.append((first + i, piece))
        longer = f.read(1)
    problems = []
    for sector, got in wrong[:_NAMED]:
        if len(got) < SECTOR:
            problems.append(f"data disk: sector {sector} is missing: the image is too short")
            continue
        inside = WRITE_FIRST <= sector < WRITE_END
        where = "inside" if inside else "outside"
        want = "the written pattern" if seed_of(sector, written) == WRITTEN \
            else "the original pattern"
        problems.append(
            f"data disk: sector {sector} ({where} the write range "
            f"[{WRITE_FIRST}, {WRITE_END})) should hold {want}, holds {_describe(got, sector)}")
    if len(wrong) > _NAMED:
        problems.append(f"data disk: {len(wrong)} sectors are wrong, the last sector {wrong[-1][0]}")
    if longer:
        problems.append(f"data disk: the image is longer than {mib} MiB")
    return problems


def _runs(first, end, written):
    """[first, end) cut where the expected seed changes."""
    cuts = {first, end}
    if written:
        cuts |= {c for c in (WRITE_FIRST, WRITE_END) if first < c < end}
    cuts = sorted(cuts)
    return list(zip(cuts, cuts[1:]))
