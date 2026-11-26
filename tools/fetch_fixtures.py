#!/usr/bin/env python3
"""Download the driver fixtures in fixtures/manifest.toml into target/fixtures/.

Every file is verified against its pinned SHA-256. A mismatch is a hard
error: the fixture is deleted and the exit status is 1. A download that
fails is tried again a few times, a little later each time: a server
that is busy for a moment is not the same as no network. One that still
cannot be made (offline) is reported and the exit status is 2, so
callers can tell "wrong bytes" from "no network". What could not be had
is named again in the last lines, where a caller that shows only the
end of the output shows it.

Usage: fetch_fixtures.py [--check]   (--check: verify only, download nothing)

Set NK_REQUIRE_FIXTURES=1 to make a missing fixture an error too. CI does,
so a run can never pass by skipping every driver test.
"""

import hashlib
import http.client
import os
import sys
import time
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures" / "manifest.toml"
CACHE = ROOT / "target" / "fixtures"
# Microsoft's symbol server only answers its own client.
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"
# How often a download is attempted, and how long to wait before the
# second attempt, in seconds; each later wait is twice the one before.
ATTEMPTS = 4
FIRST_WAIT = 2

pause = time.sleep


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
    for attempt in range(ATTEMPTS):
        if attempt:
            pause(FIRST_WAIT * 2 ** (attempt - 1))
        try:
            req = urllib.request.Request(fx["url"], headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r:
                tmp.write_bytes(r.read())
            break
        # A refused or reset connection, a time-out, a server's error
        # status, or a body that ended early.
        except (OSError, http.client.HTTPException) as e:
            tmp.unlink(missing_ok=True)
            print(f"  {fx['file']}: download failed (attempt {attempt + 1} of {ATTEMPTS}): {e}")
    else:
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
    for verdict, what in (("bad", "have the wrong bytes"), ("missing", "could not be downloaded")):
        names = [name for name, result in results.items() if result == verdict]
        if names:
            print(f"fixtures: {what}: {' '.join(names)}")
    if "bad" in results.values():
        return 1
    if "missing" in results.values():
        return 1 if os.environ.get("NK_REQUIRE_FIXTURES") else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
