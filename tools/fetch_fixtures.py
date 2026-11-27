#!/usr/bin/env python3
"""Download the driver fixtures in fixtures/manifest.toml into target/fixtures/.

Every file is verified against its pinned SHA-256. A mismatch is a hard
error: the fixture is deleted and the exit status is 1. A download that
fails is tried again, a little later each time, and for longer when the
server answers that it is busy: a server that is busy for a while is
not the same as no network. One that still
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
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures" / "manifest.toml"
CACHE = ROOT / "target" / "fixtures"
# Microsoft's symbol server only answers its own client.
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"
# How often a download is attempted, and how long to wait before the
# second attempt, in seconds; each later wait is twice the one before.
# A failure to reach the server at all (offline) gets the short
# schedule. A server that answers that it is busy (HTTP 429, or 5xx:
# Microsoft's symbol server answers 503 under load) gets the long one,
# about three minutes in all, and a wait it names (`Retry-After`, in
# seconds) when that is longer.
ATTEMPTS = 4
FIRST_WAIT = 2
BUSY_ATTEMPTS = 7
BUSY_FIRST_WAIT = 3

pause = time.sleep


def load_manifest():
    return tomllib.loads(MANIFEST.read_text())["fixture"]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retry_after(error):
    """The seconds a busy server asks to be left alone for, or 0."""
    try:
        return max(0, int(error.headers.get("Retry-After", "0")))
    except (AttributeError, ValueError):
        return 0


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
    attempt, wait = 0, 0
    while True:
        if attempt:
            pause(wait)
        attempt += 1
        try:
            req = urllib.request.Request(fx["url"], headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r:
                tmp.write_bytes(r.read())
            break
        # A refused or reset connection, a time-out, a server's error
        # status, or a body that ended early.
        except (OSError, http.client.HTTPException) as e:
            tmp.unlink(missing_ok=True)
            busy = isinstance(e, urllib.error.HTTPError) and (e.code == 429 or e.code >= 500)
            limit, first = (BUSY_ATTEMPTS, BUSY_FIRST_WAIT) if busy else (ATTEMPTS, FIRST_WAIT)
            print(f"  {fx['file']}: download failed (attempt {attempt} of {limit}): {e}")
            if attempt >= limit:
                return "missing"
            wait = first * 2 ** (attempt - 1)
            if busy:
                wait = max(wait, retry_after(e))
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
