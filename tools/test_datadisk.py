"""Unit tests for the data disk's pattern and its check (tools/datadisk.py).
Run by `make test`; nothing is booted."""

import struct
import tempfile
import unittest
from pathlib import Path

import boot_test
import datadisk
from datadisk import ORIGINAL, SECTOR, WRITE_END, WRITE_FIRST, WRITTEN

# Small, and still holding the whole write range.
MIB = 2


class Pattern(unittest.TestCase):
    def test_word_k_of_the_disk_is_the_seed_xor_k(self):
        data = datadisk.sectors(3, 2, ORIGINAL)
        self.assertEqual(len(data), 2 * SECTOR)
        words = struct.unpack("<128Q", data)
        self.assertEqual(words[0], ORIGINAL ^ (3 * 64))
        self.assertEqual(words[63], ORIGINAL ^ (3 * 64 + 63))
        self.assertEqual(words[64], ORIGINAL ^ (4 * 64))
        # The bytes, spelled out: the word index, then "ROKN".
        self.assertEqual(data[:8], bytes([0xC0, 0, 0, 0, 0x52, 0x4F, 0x4B, 0x4E]))
        self.assertEqual(datadisk.sectors(0, 1, WRITTEN)[8:16], b"\x01\0\0\0RWKN")

    def test_the_write_range_is_inside_the_smallest_disk_and_whole_sectors(self):
        self.assertLess(WRITE_FIRST, WRITE_END)
        self.assertLessEqual(WRITE_END * SECTOR, MIB << 20)
        self.assertLessEqual(MIB, datadisk.DEFAULT_MIB)
        # The seeds leave the word index readable: no overlap with it.
        for seed in (ORIGINAL, WRITTEN):
            self.assertEqual(seed & 0xFFFF_FFFF, 0)
        self.assertNotEqual(ORIGINAL, WRITTEN)


class Check(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.image = Path(self.dir.name) / "data.img"
        datadisk.create(self.image, MIB)

    def put(self, sector, data):
        with open(self.image, "r+b") as f:
            f.seek(sector * SECTOR)
            f.write(data)

    def write_range(self, seed=WRITTEN):
        self.put(WRITE_FIRST, datadisk.sectors(WRITE_FIRST, WRITE_END - WRITE_FIRST, seed))

    def verify(self, expect):
        return datadisk.verify(self.image, expect, MIB)

    def test_a_new_image_is_unchanged_and_not_written(self):
        self.assertEqual(self.image.stat().st_size, MIB << 20)
        self.assertEqual(self.verify("unchanged"), [])
        problems = self.verify("written")
        self.assertIn(f"sector {WRITE_FIRST} (inside the write range", problems[0])
        self.assertIn("should hold the written pattern, holds the original pattern", problems[0])
        self.assertEqual(
            problems[-1],
            f"data disk: {WRITE_END - WRITE_FIRST} sectors are wrong, "
            f"the last sector {WRITE_END - 1}")

    def test_the_write_range_written_is_written_and_not_unchanged(self):
        self.write_range()
        self.assertEqual(self.verify("written"), [])
        problems = self.verify("unchanged")
        self.assertIn("should hold the original pattern, holds the written pattern", problems[0])

    def test_a_changed_sector_outside_the_write_range_is_reported(self):
        for expect in ("unchanged", "written"):
            if expect == "written":
                self.write_range()
            for sector in (0, WRITE_FIRST - 1, WRITE_END, (MIB << 20) // SECTOR - 1):
                with self.subTest(expect=expect, sector=sector):
                    self.put(sector, datadisk.sectors(sector, 1, WRITTEN))
                    self.assertEqual(self.verify(expect), [
                        f"data disk: sector {sector} (outside the write range "
                        f"[{WRITE_FIRST}, {WRITE_END})) should hold the original pattern, "
                        "holds the written pattern"])
                    self.put(sector, datadisk.sectors(sector, 1, ORIGINAL))
                    self.assertEqual(self.verify(expect), [])

    def test_one_changed_byte_is_reported(self):
        self.put(7, b"\xff")
        [problem] = self.verify("unchanged")
        self.assertIn("sector 7 (outside", problem)
        self.assertIn("holds neither pattern (starts ff01", problem)

    def test_a_wrong_pattern_inside_the_write_range_is_reported(self):
        # The written pattern of another address: a write that went to
        # the wrong sector.
        self.write_range()
        self.put(WRITE_FIRST + 5, datadisk.sectors(WRITE_FIRST + 6, 1, WRITTEN))
        [problem] = self.verify("written")
        self.assertIn(f"sector {WRITE_FIRST + 5} (inside the write range", problem)
        self.assertIn("should hold the written pattern, holds neither pattern", problem)
        # Zeroes, and a sector the test did not reach.
        self.put(WRITE_FIRST + 5, bytes(SECTOR))
        self.assertIn("holds zeroes", self.verify("written")[0])
        self.put(WRITE_FIRST + 5, datadisk.sectors(WRITE_FIRST + 5, 1, ORIGINAL))
        self.assertIn("holds the original pattern", self.verify("written")[0])

    def test_an_image_of_another_size_is_reported(self):
        with open(self.image, "ab") as f:
            f.write(b"x")
        self.assertEqual(self.verify("unchanged"), [f"data disk: the image is longer than {MIB} MiB"])
        with open(self.image, "r+b") as f:
            f.truncate((MIB << 20) - SECTOR)
        [problem] = self.verify("unchanged")
        self.assertIn("is missing: the image is too short", problem)


class Machine(unittest.TestCase):
    """The disk on QEMU's command line: on the machine's AHCI controller,
    and written to its file."""

    def test_no_disk_unless_asked(self):
        for arch in ("x86_64", "aarch64"):
            command = " ".join(boot_test.qemu_command(arch, 1, False))
            self.assertNotIn("ide-hd", command)
            self.assertNotIn("ahci", command)

    def test_x86_64_uses_the_controller_q35_has(self):
        command = boot_test.qemu_command("x86_64", 1, False, disk="ahci")
        i = command.index("if=none,id=nkdata,format=raw,file=data.img")
        self.assertEqual(command[i - 1], "-drive")
        self.assertEqual(command[i + 1:i + 3], ["-device", "ide-hd,drive=nkdata,bus=ide.0"])
        self.assertNotIn("ich9-ahci,id=ahci", command)

    def test_aarch64_adds_a_controller(self):
        command = boot_test.qemu_command("aarch64", 1, False, disk="ahci")
        i = command.index("ich9-ahci,id=ahci")
        self.assertEqual(command[i + 1:i + 3], ["-device", "ide-hd,drive=nkdata,bus=ahci.0"])

    def test_writes_reach_the_file(self):
        for arch in ("x86_64", "aarch64"):
            [drive] = [a for a in boot_test.qemu_command(arch, 1, True, disk="ahci")
                       if "id=nkdata" in a and a.startswith("if=")]
            self.assertNotIn("snapshot", drive)
            self.assertNotIn("readonly", drive)


if __name__ == "__main__":
    unittest.main()
