"""Boot the packaged SDL client, upload its outbox, and watch a loopback replay link.

python3 crimson-core/checks/native_client_network.py <native binary> [asset directory]
Linux CI runs this under Xvfb; all leaderboard requests go to the loopback mock.
"""

import contextlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN, QUEUED = "b" * 64, "a" * 64


def main():
    binary = Path(sys.argv[1]).resolve()
    replay = (ROOT / "tests/fixtures/replays/quest-1.1-completed.crd").read_bytes()
    with tempfile.TemporaryDirectory(prefix="crimson-client-network-") as folder:
        root = Path(folder)
        game, captures = root / "game", root / "captures"
        game.mkdir()
        captures.mkdir()
        for name in ("crimson.paq", "sfx.paq", "music.paq"):
            if len(sys.argv) > 2:
                shutil.copy2(Path(sys.argv[2]) / name, game / name)
            else:
                # The distributed 1.9.93 files, as checks/game_files.py uses.
                request = urllib.request.Request(
                    f"https://paq.crimson.banteg.xyz/v1.9.93/{name}", headers={"User-Agent": "crimsonland-decompile"},
                )
                with urllib.request.urlopen(request, timeout=60) as source:
                    (game / name).write_bytes(source.read())
        outbox = game / "leaderboard/outbox"
        outbox.mkdir(parents=True)
        envelope = {
            "replay": "fixture",
            "name": "native smoke",
            "public_key": "test key",
            "signature": "test signature",
        }
        (outbox / f"{QUEUED}.json").write_text(json.dumps(envelope))
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                calls.append((self.command, self.path, body))
                self.reply(b"{}")

            def do_GET(self):
                calls.append((self.command, self.path, b""))
                if self.path == f"/runs/{RUN}.crd":
                    self.reply(replay)
                elif self.path == f"/api/runs/{RUN}":
                    self.reply(json.dumps({"name": "native smoke", "rank": 2, "accepted_at": 1767225600000}).encode())
                else:
                    self.reply(b"{}", 404)

            def reply(self, data, status=200):
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(data)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        env = {
            **os.environ,
            "CRIMSON_LEADERBOARD_URL": origin + "/api",
            "CRIMSON_CAPTURE": str(captures),
            "CRIMSON_CAPTURE_FRAMES": "600",
            "CRIMSON_MUTE": "1",
        }
        try:
            done = subprocess.run(
                [str(binary), str(game), "--watch", origin + "/play/?watch=" + RUN],
                env=env,
                capture_output=True,
                check=False,
                timeout=90,
            )
            if done.returncode:
                raise RuntimeError(done.stderr.decode(errors="replace"))
            assert (game / f"replays/online/{RUN}.crd").read_bytes() == replay
            assert not list(outbox.glob("*.json")), "startup upload left the outbox queued"
            assert any(
                method == "POST" and path == "/api/runs" and json.loads(body) == envelope
                for method, path, body in calls
            )
            assert any(path == f"/api/runs/{RUN}" for _, path, _ in calls)
            state = json.loads((captures / "frame_600.json").read_text())
            assert state["watch_status"] in (0, 1), state
            assert state["watch_tick"] > 0 and state["watch_ticks"] > 0, state
            assert (captures / "frame_600.ppm").stat().st_size > 1024
            print(json.dumps({"uploaded": 1, "downloaded": 1, **state}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
