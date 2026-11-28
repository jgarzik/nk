"""Unit tests for the names tools/mkesp.py gives boot files. Run by
`make test`; no image is built."""

import re
import tomllib
import unittest

import mkesp
import negpe

MANIFEST = tomllib.loads((mkesp.ROOT / "fixtures" / "manifest.toml").read_text())["fixture"]
BOOTINFO = (mkesp.ROOT / "lib" / "bootinfo" / "lib.rs").read_text()


def limit(name):
    """A constant of lib/bootinfo, which the loader is held to."""
    return int(re.search(rf"^pub const {name}: usize = (\d+);$", BOOTINFO, re.M)[1])


class BootNames(unittest.TestCase):
    def test_a_fixture_keeps_its_name_and_its_files_extension(self):
        def name(name, file):
            return mkesp.boot_name({"name": name, "file": file})

        self.assertEqual(name("null", "null.x64.sys"), "null.sys")
        self.assertEqual(name("pshed", "pshed.x64.dll"), "pshed.dll")
        self.assertEqual(name("pshed", "pshed.dll"), "pshed.dll")
        # Only what follows the last dot of the file is taken; the name
        # is used whole, dots and all.
        self.assertEqual(name("nkc-lib", "nkc-lib.arm64.sys"), "nkc-lib.sys")
        self.assertEqual(name("a.b", "a.b.x64.SYS"), "a.b.SYS")

    def test_the_fixtures_a_boot_is_given(self):
        manifest = [
            {"name": "null", "arch": "x86_64", "file": "null.x64.sys"},
            {"name": "pshed", "arch": "x86_64", "file": "pshed.x64.dll"},
            {"name": "held", "arch": "x86_64", "file": "held.x64.sys", "boot": False},
            {"name": "sioctl", "arch": "x86_64", "file": "sioctl.x64.sys"},
            {"name": "sioctl", "arch": "aarch64", "file": "sioctl.arm64.sys"},
            {"name": "kmdf-echo", "arch": "x86_64", "file": "kmdf-echo.x64.sys", "boot": False},
            {"name": "table", "arch": "x86_64", "file": "table.x64.txt", "kind": "abi-table"},
        ]
        self.assertEqual(
            [(name, fx["file"]) for name, fx in mkesp.boot_files("x86_64", manifest)],
            [("null.sys", "null.x64.sys"), ("pshed.dll", "pshed.x64.dll"),
             ("sioctl.sys", "sioctl.x64.sys"), ("wrongarch.sys", "sioctl.arm64.sys")])
        self.assertEqual(
            [(name, fx["file"]) for name, fx in mkesp.boot_files("aarch64", manifest)],
            [("wrongarch.sys", "sioctl.x64.sys"), ("sioctl.sys", "sioctl.arm64.sys")])

    def test_the_manifests_boot_files_are_images_the_loader_can_hand_over(self):
        for arch in mkesp.BOOT_NAME:
            names = [name for name, _ in mkesp.boot_files(arch, MANIFEST)]
            names += [name for name, _, _ in negpe.NEGATIVE_FIXTURES]
            with self.subTest(arch=arch):
                self.assertTrue(names)
                # The kernel finds a boot file by name, whatever its case.
                self.assertEqual(len(names), len({n.lower() for n in names}))
                for name in names:
                    self.assertRegex(name, r"\.(sys|dll)$")
                    # The loader cuts a longer name short.
                    self.assertLessEqual(len(name), limit("MODULE_NAME_LEN"), name)
                # Plus the hive and overlay.
                self.assertLessEqual(len(names) + 2, limit("MAX_MODULES"))


if __name__ == "__main__":
    unittest.main()
