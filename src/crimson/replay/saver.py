"""Writes finished runs' replays off the frame.

Compressing a long run's replay takes a few hundred ms, and its checkpoint sidecar several seconds, so the run's
end only snapshots what it recorded and a worker thread encodes and writes it. zstd releases the GIL while it
compresses, which is nearly all of that time.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

import msgspec

from .checkpoints import ReplayCheckpoints, default_checkpoints_path, dump_checkpoints_file
from .codec import ReplayCodecError, dump_replay_file
from .types import Replay


class ReplaySaveJob(msgspec.Struct, frozen=True):
    path: Path
    replay: Replay
    checkpoints: ReplayCheckpoints | None = None

    def run(self) -> list[str]:
        """Write the replay, then its sidecar; returns the console lines to log."""
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            dump_replay_file(path, self.replay)
        except ReplayCodecError as exc:
            # Only a run of many hours outgrows the format's size ceiling.
            return [f"replay: not saved ({exc})"]
        saved = [path]
        if self.checkpoints is not None:
            checkpoints_path = default_checkpoints_path(path)
            dump_checkpoints_file(checkpoints_path, self.checkpoints)
            saved.append(checkpoints_path)
        return [f"replay: saved {saved_path}" for saved_path in saved]


class ReplaySaver:
    """Runs save jobs on one worker, in the order runs finished.

    The console is not thread-safe, so the lines each job logs come back through `drain` on the main thread.
    """

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="replay-save")
        self._pending: list[Future[list[str]]] = []

    def submit(self, job: ReplaySaveJob) -> None:
        self._pending.append(self._executor.submit(job.run))

    def drain(self) -> list[str]:
        """The lines of the jobs finished so far, in submission order; a job's error is raised here."""
        lines: list[str] = []
        while self._pending and self._pending[0].done():
            lines += self._pending.pop(0).result()
        return lines

    def close(self) -> list[str]:
        """Wait for every submitted job, so quitting right after a run still writes its replay."""
        self._executor.shutdown(wait=True)
        return self.drain()


__all__ = ["ReplaySaveJob", "ReplaySaver"]
