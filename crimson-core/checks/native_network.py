"""Exercise the desktop's real HTTP worker against a loopback service, without SDL or game assets.

python3 crimson-core/checks/native_network.py
"""

import contextlib
import http.server
import json
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
RUN = "a" * 64


class NativeNetwork(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="crimson-network-")
        cls.binary = Path(cls.build.name) / "network"
        curl = "/usr/bin/curl-config" if sys.platform == "darwin" else "curl-config"
        flags = shlex.split(subprocess.check_output([curl, "--cflags", "--libs"], text=True))
        subprocess.run(
            [
                shutil.which("clang++") or "",
                "-std=c++17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-missing-field-initializers",
                "-pthread",
                "-I" + str(CORE / "client"),
                str(CORE / "checks/native_network.cpp"),
                str(CORE / "client/network.cpp"),
                *flags,
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="crimson-network-game-")
        self.root = Path(self.folder.name)
        self.calls = []
        self.status, self.reply, self.delay = 200, b"{}", 0
        self.upload_delay = 0
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.answer()

            def do_POST(self):
                self.answer()

            def answer(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                test.calls.append((self.command, self.path, body, self.headers))
                time.sleep(test.upload_delay if self.path == "/api/runs" else test.delay)
                self.send_response(test.status)
                self.send_header("Content-Length", str(len(test.reply)))
                if test.status == 302:
                    self.send_header("Location", test.api + "/redirected")
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(test.reply)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.api = f"http://127.0.0.1:{self.server.server_port}/api"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.folder.cleanup()

    def request(self, kind, body="", api=None):
        done = subprocess.run(
            [str(self.binary), api or self.api, str(self.root), str(kind), body],
            capture_output=True,
            check=True,
            timeout=20,
        )
        status, _, answer = done.stdout.partition(b"\n")
        ok, code = map(int, status.split())
        return bool(ok), code, answer

    def queue(self):
        source = self.root / "leaderboard/outbox" / f"{RUN}.json"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(json.dumps({"name": "runner", "replay": "bytes", "signature": "signed"}))
        return source

    def test_upload_success_and_duplicate(self):
        for status in (200, 201, 409):
            with self.subTest(status=status):
                source = self.queue()
                self.status = status
                self.assertTrue(self.request(0)[0])
                self.assertFalse(source.exists())
                method, path, body, headers = self.calls[-1]
                self.assertEqual((method, path), ("POST", "/api/runs"))
                self.assertEqual(json.loads(body)["signature"], "signed")
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertEqual(headers["User-Agent"], "crimsonland/test")

    def test_transient_uploads_stay_queued(self):
        for status in (429, 500, 503, 302):
            with self.subTest(status=status):
                source = self.queue()
                original = source.read_bytes()
                self.status = status
                self.assertFalse(self.request(0)[0])
                self.assertEqual(source.read_bytes(), original)
                self.assertFalse(any(call[1] == "/api/redirected" for call in self.calls))

    def test_rejection_saved_before_removal(self):
        source = self.queue()
        self.status, self.reply = 422, json.dumps({"reason": 'bad "run"\n\u00e9'}).encode()
        self.assertTrue(self.request(0)[0])
        self.assertFalse(source.exists())
        rejected = json.loads((self.root / "leaderboard/rejected" / source.name).read_bytes())
        self.assertEqual(rejected["reason"], 'bad "run"\n\u00e9')
        self.assertEqual(rejected["signature"], "signed")

    def test_rejection_write_failure_keeps_queue(self):
        source = self.queue()
        (self.root / "leaderboard/rejected").write_text("not a directory")
        self.status = 403
        self.assertFalse(self.request(0)[0])
        self.assertTrue(source.exists())

    def test_malformed_queue_stays(self):
        source = self.queue()
        source.write_text("not JSON")
        self.assertFalse(self.request(0)[0])
        self.assertTrue(source.exists())
        self.assertEqual(self.calls, [])

    def test_bad_queue_does_not_block_later_run(self):
        source = self.queue()
        (source.parent / ("0" * 64 + ".json")).write_text("broken")
        self.assertFalse(self.request(0)[0])
        self.assertFalse(source.exists())
        self.assertEqual(len(self.calls), 1)

    def test_partial_entry_is_ignored(self):
        source = self.queue()
        source.rename(source.with_suffix(".json.part"))
        self.assertTrue(self.request(0)[0])
        self.assertEqual(self.calls, [])

    def test_scores_fetch_with_broken_outbox(self):
        (self.root / "leaderboard").symlink_to(self.root / "missing")
        self.reply = b'{"scores":[]}'
        self.assertTrue(self.request(1, "{}")[0])
        self.assertEqual(self.calls[-1][1], "/api/scores")

    def test_case_insensitive_game_paths(self):
        source = self.queue()
        (self.root / "leaderboard").rename(self.root / "Leaderboard")
        self.assertTrue(self.request(0)[0])
        self.assertFalse((self.root / "Leaderboard/outbox" / source.name).exists())

    def test_scores_body_and_response(self):
        self.reply = b'{"scores": []}'
        body = '{"board":"quests-hardcore","quest":"1.1"}'
        ok, code, answer = self.request(1, body)
        self.assertTrue(ok)
        self.assertEqual((code, answer), (200, self.reply))
        self.assertEqual(self.calls[-1][:3], ("POST", "/api/scores", body.encode()))
        self.reply = b"x" * ((4 << 20) + 1)
        self.assertFalse(self.request(1, body)[0])

    def test_profile_challenge(self):
        self.reply = json.dumps({"challenge": RUN}).encode()
        self.assertEqual(self.request(2, '{"public_key":"key"}'), (True, 200, RUN.encode()))
        for challenge in ("bad", "a" * 65, "a" * 63 + "\u0000"):
            self.reply = json.dumps({"challenge": challenge}).encode()
            self.assertFalse(self.request(2, "{}")[0])

    def test_profile_url_stays_on_service(self):
        origin = self.api.removesuffix("/api")
        self.reply = json.dumps({"url": origin + "/login/" + RUN}).encode()
        self.assertTrue(self.request(3, "{}")[0])
        for url in (
            "https://evil.example/",
            origin + ".evil/",
            "file:///tmp/a",
            "/relative",
            origin + "\u0000.evil/",
            origin.replace("http://", "http://user@"),
            origin.replace("http:", "https:"),
        ):
            with self.subTest(url=url):
                self.reply = json.dumps({"url": url}).encode()
                self.assertFalse(self.request(3, "{}")[0])

    def test_replay_download_and_missing(self):
        self.reply = b"\x28\xb5\x2f\xfd\x00binary replay"
        self.assertTrue(self.request(4, RUN)[0])
        target = self.root / "replays/online" / f"{RUN}.crd"
        self.assertEqual(target.read_bytes(), self.reply)
        self.assertEqual(self.calls[-1][:2], ("GET", f"/runs/{RUN}.crd"))
        self.status = 404
        self.assertEqual(self.request(4, "b" * 64)[:2], (False, 404))
        self.assertFalse((target.parent / ("b" * 64 + ".crd")).exists())
        self.assertFalse(self.request(4, "../escape")[0])
        self.assertEqual(len(self.calls), 2)

    def test_oversized_replay_keeps_existing_file(self):
        self.reply = b"old"
        self.assertTrue(self.request(4, RUN)[0])
        self.reply = b"x" * ((16 << 20) + 1)
        self.assertFalse(self.request(4, RUN)[0])
        target = self.root / "replays/online" / f"{RUN}.crd"
        self.assertEqual(target.read_bytes(), b"old")
        self.assertEqual(list(target.parent.iterdir()), [target])

    def test_symlink_replay_path_refused(self):
        (self.root / "replays").symlink_to(self.root / "elsewhere")
        self.reply = b"replay"
        self.assertFalse(self.request(4, RUN)[0])
        self.assertFalse((self.root / "elsewhere").exists())

    def test_profile_is_not_blocked_by_upload(self):
        self.queue()
        self.upload_delay = 4
        self.reply = json.dumps({"challenge": RUN}).encode()
        self.assertEqual(self.request("parallel"), (True, 200, RUN.encode()))

    def test_shutdown_after_lane_wakeup(self):
        subprocess.run([str(self.binary), self.api, str(self.root), "shutdown", ""], check=True, timeout=5)

    def test_shutdown_cancels_inflight_request(self):
        self.delay = 4
        start = time.monotonic()
        subprocess.run([str(self.binary), self.api, str(self.root), "cancel", RUN], check=True, timeout=3)
        self.assertLess(time.monotonic() - start, 3)
        self.assertFalse((self.root / "replays").exists())

    def test_untrusted_tls_certificate_refused(self):
        cert, key = self.root / "cert.pem", self.root / "key.pem"
        subprocess.run(
            [
                shutil.which("openssl") or "",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.assertFalse(self.request(1, "{}", self.api.replace("http:", "https:"))[0])
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
