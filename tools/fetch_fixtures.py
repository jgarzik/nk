#!/usr/bin/env python3
"""Download the driver fixtures in fixtures/manifest.toml into target/fixtures/.

Every file is verified against its pinned SHA-256. A mismatch is a hard
error: the fixture is deleted and the exit status is 1. A download that
cannot be made (offline) is reported and the exit status is 2, so callers
can tell "wrong bytes" from "no network".

Usage: fetch_fixtures.py [--check]   (--check: verify only, download nothing)
"""

import hashlib
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures" / "manifest.toml"
CACHE = ROOT / "target" / "fixtures"
# Microsoft's symbol server only answers its own client.
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"


def load_manifest():
    return tomllib.loads(MANIFEST.read_text())["fixture"]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(fx):
    """Return 'ok', 'fetched', 'missing' or 'bad'."""
    dest = CACHE / fx["file"]
    if dest.exists():
        if sha256(dest) == fx["sha256"]:
            return "ok"
        dest.unlink()
    if "--check" in sys.argv:
        return "missing"
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        req = urllib.request.Request(fx["url"], headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as r:
            tmp.write_bytes(r.read())
    except OSError as e:
        tmp.unlink(missing_ok=True)
        print(f"  {fx['file']}: download failed: {e}")
        return "missing"
    if sha256(tmp) != fx["sha256"]:
        got = sha256(tmp)
        tmp.unlink()
        print(f"  {fx['file']}: SHA-256 mismatch\n    want {fx['sha256']}\n    got  {got}")
        return "bad"
    tmp.replace(dest)
    return "fetched"


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    results = {}
    for fx in load_manifest():
        results[fx["file"]] = fetch(fx)
        print(f"{results[fx['file']]:8} {fx['file']}")
    if "bad" in results.values():
        return 1
    return 2 if "missing" in results.values() else 0


if __name__ == "__main__":
    sys.exit(main())
