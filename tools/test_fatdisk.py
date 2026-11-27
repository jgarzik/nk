"""Checks on tools/fatdisk.py: a made disk passes its check, and a disk
whose volume changed fails it, naming what changed. Run by `make test`;
needs the host's sfdisk, mtools and fsck.fat."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import fatdisk

TARGET = Path(__file__).resolve().parent.parent / "target"
TOOLS = ("sfdisk", "mformat", "mcopy", "mtype", "mdir", "mdel", "fsck.fat")


@unittest.skipUnless(all(shutil.which(t) for t in TOOLS), "host disk tools absent")
class FatDisk(unittest.TestCase):
    def setUp(self):
        TARGET.mkdir(exist_ok=True)
        self.dir = tempfile.TemporaryDirectory(dir=TARGET)
        self.addCleanup(self.dir.cleanup)

    def image(self, layout):
        path = Path(self.dir.name) / f"{layout}.img"
        fatdisk.create(path, layout)
        return path

    def test_each_layout_passes_as_made(self):
        for layout in fatdisk.LAYOUTS:
            with self.subTest(layout=layout):
                path = self.image(layout)
                self.assertEqual(fatdisk.verify(path, "fat-unchanged"), [])
                table = subprocess.run(["sfdisk", "-d", str(path)], capture_output=True,
                                       text=True, check=True).stdout
                self.assertIn(f"start=        {fatdisk.START}, size=      {fatdisk.LENGTH}", table)

    def test_the_volume_is_fat32(self):
        path = self.image("fat32-mbr")
        boot = path.read_bytes()[fatdisk.START * 512:][:512]
        self.assertEqual(boot[82:90], b"FAT32   ")
        self.assertEqual(int.from_bytes(boot[28:32], "little"), fatdisk.START)
        self.assertEqual(boot[510:512], b"\x55\xaa")

    def test_a_changed_file_is_named(self):
        path = self.image("fat32-mbr")
        data = bytearray(path.read_bytes())
        at = data.find(fatdisk.FILES["PATTERN.BIN"][:512], fatdisk.START * 512)
        self.assertGreater(at, 0)
        data[at] ^= 0xFF
        path.write_bytes(bytes(data))
        self.assertEqual(fatdisk.verify(path, "fat-unchanged"),
                         ["FAT disk: PATTERN.BIN holds other bytes than it was given"])

    def test_a_deleted_file_is_named(self):
        path = self.image("fat32-gpt")
        subprocess.run(["mdel", "-i", f"{path}@@{fatdisk.START * 512}", "::HELLO.TXT"],
                       check=True, env=dict(os.environ, MTOOLS_SKIP_CHECK="1"))
        self.assertEqual(fatdisk.verify(path, "fat-unchanged"), ["FAT disk: HELLO.TXT is gone"])


if __name__ == "__main__":
    unittest.main()
