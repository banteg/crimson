"""Signed ranked-run uploads and the site login (docs/rewrite/leaderboard-identity.md).

A finished ranked run is held from its end until its results screen closes, so it uploads under the name typed
there. Then one worker thread signs it into the outbox and uploads every queued run; a run the service cannot be
reached for stays in the outbox and goes with a later pass. The console is not thread-safe, so the worker's lines
come back through `drain` on the main thread, as the replay saver's do.

The high score screen's Update scores runs `sync` on the same thread, as the original's `highscore_sync_worker`
did: it sends the waiting runs, then receives a verified board's best runs for the screen to show.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from enum import IntEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import msgspec

from grim.atomic_write import atomic_write_bytes

from .. import __version__
from ..replay.codec import encode_replay_payload, zstd_pack
from ..replay.types import Replay
from .identity import Identity

LEADERBOARD_URL = "https://crimson.land/api"
# Seconds between upload passes while runs wait in the outbox.
RETRY_INTERVAL_S = 600.0
_TIMEOUT_S = 10.0

type Transport = Callable[[str, dict[str, Any]], tuple[int, dict[str, Any]]]


class LeaderboardError(OSError):
    pass


def leaderboard_url() -> str:
    """The service's API root; `CRIMSON_LEADERBOARD_URL` points the game at another one, such as a local Worker, and
    an empty value keeps every run on the machine."""
    return os.environ.get("CRIMSON_LEADERBOARD_URL", LEADERBOARD_URL).rstrip("/")


def post_json(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """POST `body` as JSON; the status and the JSON object answered. Raises OSError when the service is unreachable."""
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": f"crimsonland/{__version__}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_S) as response:
            return response.status, _json_object(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json_object(exc.read())


def _json_object(data: bytes) -> dict[str, Any]:
    # Proxies in front of the service answer some errors with HTML, which reads as an empty answer.
    try:
        value = json.loads(data)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


class _Report(msgspec.Struct, frozen=True):
    lines: list[str]
    waiting: int


class SyncStatus(IntEnum):
    """`online_sync_status`: the high score screen's line while Update scores runs; the port has no "Connected..."."""

    IDLE = 0
    CONNECTING = 1
    SENDING = 3
    RECEIVING = 4
    DONE = 5
    FAILED = 6


class OnlineScore(msgspec.Struct, frozen=True):
    """A verified board's run with a high score record's fields; `score` is the board's (experience, or a quest's
    final time) and `accepted_at` is in Unix milliseconds."""

    name: str
    score: int
    elapsed_ms: int
    experience: int
    most_used_weapon_id: int
    shots_fired: int
    shots_hit: int
    kills: int
    accepted_at: int


# A verified board: its name and, for quests, the "major.minor" level.
type Board = tuple[str, str]


class Leaderboard:
    def __init__(self, base_dir: Path, *, url: str | None = None, transport: Transport = post_json) -> None:
        self.identity = Identity.load_or_create(base_dir)
        self._outbox = base_dir / "leaderboard" / "outbox"
        self._rejected = base_dir / "leaderboard" / "rejected"
        self._url = leaderboard_url() if url is None else url
        self._transport = transport
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="leaderboard")
        # Logins run beside uploads, so a long upload pass never keeps the Profile button waiting.
        self._login_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="leaderboard-login")
        self._pending: list[Future[_Report]] = []
        self._held: Replay | None = None
        self._next_pass_s = 0.0
        self.waiting = self._waiting_count()
        # Written by the worker, read by the high score screen.
        self.sync_status = SyncStatus.IDLE
        self.scores: dict[Board, list[OnlineScore]] = {}

    def hold(self, replay: Replay) -> None:
        """Keep a finished ranked run until its results screen closes and its name is known."""
        self._held = replay

    def release(self, name: str) -> None:
        """Queue the held run, if any, under `name`, then upload."""
        if self._queue_held(name) and self._url:
            self._pending.append(self._executor.submit(self._upload_pass))

    def tick(self, now_s: float) -> None:
        """Start an upload pass at launch and every `RETRY_INTERVAL_S` while runs wait and none is running."""
        if self._url and self.waiting and not self._pending and now_s >= self._next_pass_s:
            self._next_pass_s = now_s + RETRY_INTERVAL_S
            self._pending.append(self._executor.submit(self._upload_pass))

    def sync(self, board: Board | None) -> None:
        """Send the waiting runs, then receive `board`'s best runs into `scores`; `sync_status` follows along."""
        if not self._url:
            self.sync_status = SyncStatus.FAILED
            return
        self.sync_status = SyncStatus.CONNECTING
        self._pending.append(self._executor.submit(self._sync, board))

    def login(self) -> Future[str]:
        """The one-time link that opens the site signed in as this key."""
        return self._login_executor.submit(self._login)

    def drain(self) -> list[str]:
        """The console lines of the finished jobs, in order; a job's error is raised here."""
        lines: list[str] = []
        while self._pending and self._pending[0].done():
            report = self._pending.pop(0).result()
            lines += report.lines
            self.waiting = report.waiting
        return lines

    def close(self, name: str) -> list[str]:
        """Queue a run still held under `name` and finish the started jobs; passes not yet started are dropped."""
        self._queue_held(name)
        self._login_executor.shutdown(wait=False, cancel_futures=True)
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._pending = [future for future in self._pending if not future.cancelled()]
        return self.drain()

    def _queue_held(self, name: str) -> bool:
        replay, self._held = self._held, None
        if replay is None:
            return False
        self._pending.append(self._executor.submit(self._queue, replay, name))
        return True

    def _waiting_count(self) -> int:
        return sum(1 for _ in self._outbox.glob("*.json")) if self._outbox.is_dir() else 0

    def _queue(self, replay: Replay, name: str) -> _Report:
        payload = encode_replay_payload(replay)
        run_id = hashlib.sha256(payload).hexdigest()
        envelope = {
            "replay": base64.b64encode(zstd_pack(payload)).decode("ascii"),
            "name": name,
            "public_key": self.identity.public_key.hex(),
            "signature": self.identity.sign_run(payload, name).hex(),
        }
        self._outbox.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(self._outbox / f"{run_id}.json", json.dumps(envelope).encode())
        return _Report([f"leaderboard: queued run {run_id[:12]} as {name!r}"], self._waiting_count())

    def _upload_pass(self) -> _Report:
        lines: list[str] = []
        for path in sorted(self._outbox.glob("*.json")) if self._outbox.is_dir() else ():
            run = path.stem[:12]
            try:
                status, answer = self._transport(f"{self._url}/runs", json.loads(path.read_bytes()))
            except OSError as exc:
                lines.append(f"leaderboard: can't reach {self._url} ({exc}); runs wait in {self._outbox}")
                break
            if status in (200, 201):
                path.unlink()
                lines.append(f"leaderboard: uploaded run {run}")
            elif status == 409:
                path.unlink()
                lines.append(f"leaderboard: run {run} was already uploaded")
            elif 400 <= status < 500 and status != 429:
                # The service will never take this run; keep it, with the reason, out of the outbox.
                reason = str(answer.get("reason", f"HTTP {status}"))
                self._rejected.mkdir(parents=True, exist_ok=True)
                atomic_write_bytes(self._rejected / path.name, json.dumps({**json.loads(path.read_bytes()), "reason": reason}).encode())
                path.unlink()
                lines.append(f"leaderboard: run {run} rejected ({reason})")
            else:
                # A service error, or the service asking to slow down (429): the runs wait.
                lines.append(f"leaderboard: service error (HTTP {status}); runs wait in {self._outbox}")
                break
        return _Report(lines, self._waiting_count())

    def _sync(self, board: Board | None) -> _Report:
        self.sync_status = SyncStatus.SENDING
        sent = self._upload_pass()
        if board is None:
            self.sync_status = SyncStatus.DONE
            return sent
        self.sync_status = SyncStatus.RECEIVING
        name, quest = board
        try:
            status, answer = self._transport(f"{self._url}/scores", {"board": name, "quest": quest})
        except OSError as exc:
            self.sync_status = SyncStatus.FAILED
            return _Report([*sent.lines, f"leaderboard: can't reach {self._url} ({exc})"], sent.waiting)
        if status != 200:
            self.sync_status = SyncStatus.FAILED
            return _Report([*sent.lines, f"leaderboard: scores: HTTP {status}"], sent.waiting)
        scores = msgspec.convert(answer["scores"], list[OnlineScore])
        self.scores[board] = scores
        self.sync_status = SyncStatus.DONE
        return _Report([*sent.lines, f"leaderboard: received {len(scores)} {f'{name} {quest}'.strip()} scores"], sent.waiting)

    def _login(self) -> str:
        if not self._url:
            raise LeaderboardError("no leaderboard service is configured")
        public_key = self.identity.public_key.hex()
        challenge = self._call("auth/challenge", {"public_key": public_key})["challenge"]
        signature = self.identity.sign_login(challenge).hex()
        url = self._call("auth/login", {"public_key": public_key, "challenge": challenge, "signature": signature})["url"]
        # The game opens this in the browser, so it must lead to the service, never anywhere a response points.
        service = urlparse(self._url)
        link = urlparse(url)
        if (link.scheme, link.netloc) != (service.scheme, service.netloc):
            raise LeaderboardError(f"login link {url!r} is not on {service.netloc}")
        return url

    def _call(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        status, answer = self._transport(f"{self._url}/{endpoint}", body)
        if status != 200:
            raise LeaderboardError(f"{endpoint}: HTTP {status} {answer.get('reason', '')}".rstrip())
        return answer


__all__ = [
    "LEADERBOARD_URL",
    "Board",
    "Leaderboard",
    "LeaderboardError",
    "OnlineScore",
    "SyncStatus",
    "leaderboard_url",
    "post_json",
]
