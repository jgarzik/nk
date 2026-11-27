"""Unit tests for tools/fetch_fixtures.py: what a download that fails does.

No network: the opener and the pause between attempts are replaced.
Run by `make test`.
"""

import contextlib
import hashlib
import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import fetch_fixtures

BYTES = b"a driver's bytes"
SHA = hashlib.sha256(BYTES).hexdigest()


class Answer:
    """What `urlopen` gives back: a context manager with `read`."""

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.data


class Server:
    """Fails the first `failures` requests, then answers with `data`."""

    def __init__(self, failures, data=BYTES):
        self.failures = failures
        self.data = data
        self.requests = 0

    def __call__(self, request, timeout):
        self.requests += 1
        if self.requests <= self.failures:
            raise TimeoutError("timed out")
        return Answer(self.data)


class Busy:
    """Answers the first `busy` requests with HTTP 503 (and a
    `Retry-After` of `after` seconds, if given), then with `data`."""

    def __init__(self, busy, after=None, data=BYTES):
        self.busy = busy
        self.after = after
        self.data = data
        self.requests = 0

    def __call__(self, request, timeout):
        self.requests += 1
        if self.requests <= self.busy:
            headers = {} if self.after is None else {"Retry-After": str(self.after)}
            raise urllib.error.HTTPError(request.full_url, 503, "Service Unavailable", headers, None)
        return Answer(self.data)


class Fetch(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.TemporaryDirectory()
        self.addCleanup(self.cache.cleanup)
        self.pauses = []
        patches = [
            mock.patch.object(fetch_fixtures, "CACHE", Path(self.cache.name)),
            mock.patch.object(fetch_fixtures, "pause", self.pauses.append),
            mock.patch.object(fetch_fixtures.sys, "argv", ["fetch_fixtures.py"]),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def fetch(self, server, sha=SHA, name="a.sys"):
        fixture = {"file": name, "url": "https://example.invalid/a.sys", "sha256": sha}
        with mock.patch.object(fetch_fixtures.urllib.request, "urlopen", server):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                result = fetch_fixtures.fetch(fixture)
        return result, out.getvalue()

    def test_a_download_that_fails_at_first_is_tried_again(self):
        server = Server(failures=2)
        result, _ = self.fetch(server)
        self.assertEqual(result, "fetched")
        self.assertEqual(server.requests, 3)
        self.assertEqual((Path(self.cache.name) / "a.sys").read_bytes(), BYTES)
        # It waited before each new attempt, longer each time.
        self.assertEqual(len(self.pauses), 2)
        self.assertLess(self.pauses[0], self.pauses[1])

    def test_a_download_that_never_succeeds_is_missing_after_every_attempt(self):
        server = Server(failures=1000)
        result, said = self.fetch(server)
        self.assertEqual(result, "missing")
        self.assertEqual(server.requests, fetch_fixtures.ATTEMPTS)
        # No pause after the last attempt, and nothing left behind.
        self.assertEqual(len(self.pauses), fetch_fixtures.ATTEMPTS - 1)
        self.assertEqual(list(Path(self.cache.name).iterdir()), [])
        self.assertIn("download failed", said)

    def test_a_busy_server_is_waited_out(self):
        # Microsoft's symbol server answers 503 for a while when it is
        # busy: CI once lost a run to four of them in fourteen seconds.
        server = Busy(busy=6)
        result, _ = self.fetch(server)
        self.assertEqual(result, "fetched")
        self.assertEqual(server.requests, 7)
        self.assertGreaterEqual(sum(self.pauses), 60)

    def test_a_busy_server_s_retry_after_is_honoured(self):
        server = Busy(busy=1, after=45)
        result, _ = self.fetch(server)
        self.assertEqual(result, "fetched")
        self.assertGreaterEqual(self.pauses[0], 45)

    def test_no_network_is_not_waited_for_long(self):
        # Offline, every fixture fails at once: a few short tries each.
        server = Server(failures=1000)
        self.fetch(server)
        self.assertLess(sum(self.pauses), 30)

    def test_wrong_bytes_are_not_asked_for_again(self):
        server = Server(failures=0, data=b"other bytes")
        result, said = self.fetch(server)
        self.assertEqual(result, "bad")
        self.assertEqual(server.requests, 1)
        self.assertEqual(self.pauses, [])
        self.assertIn("SHA-256 mismatch", said)

    def test_the_last_lines_name_what_could_not_be_had(self):
        # The gate shows the end of a failed step's output: the fixtures
        # that failed must be there, not scrolled away above the ones
        # that were fetched after them.
        manifest = [
            {"file": "gone.sys", "url": "https://example.invalid/gone.sys", "sha256": SHA},
        ] + [
            {"file": f"ok{n}.sys", "url": "https://example.invalid/ok.sys", "sha256": SHA}
            for n in range(50)
        ]

        def server(request, timeout):
            if request.full_url.endswith("gone.sys"):
                raise TimeoutError("timed out")
            return Answer(BYTES)

        with mock.patch.object(fetch_fixtures, "load_manifest", lambda: manifest):
            with mock.patch.object(fetch_fixtures.urllib.request, "urlopen", server):
                with mock.patch.dict(fetch_fixtures.os.environ, {"NK_REQUIRE_FIXTURES": "1"}):
                    with contextlib.redirect_stdout(io.StringIO()) as out:
                        status = fetch_fixtures.main()
        self.assertEqual(status, 1)
        last = out.getvalue().splitlines()[-3:]
        self.assertTrue(any("gone.sys" in line for line in last), last)


if __name__ == "__main__":
    unittest.main()
