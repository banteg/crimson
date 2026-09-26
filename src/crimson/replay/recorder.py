from __future__ import annotations

from ..sim.run_result import RunResult
from ..sim.run_spec import RunSpec
from .types import REPLAY_FORMAT_VERSION, Replay, ReplayTick, current_replay_game_version


class ReplayRecorder:
    def __init__(self, run: RunSpec, *, game_version: str | None = None) -> None:
        self._run = run
        self._game_version = current_replay_game_version() if game_version is None else game_version
        self._ticks: list[ReplayTick] = []

    @property
    def run(self) -> RunSpec:
        return self._run

    @property
    def tick_index(self) -> int:
        return len(self._ticks)

    def record(self, tick: ReplayTick) -> int:
        """Append one tick; returns its index."""

        if len(tick.inputs) != self._run.player_count:
            raise ValueError(f"expected {self._run.player_count} player inputs, got {len(tick.inputs)}")
        self._ticks.append(tick)
        return len(self._ticks) - 1

    def finish(self, result: RunResult) -> Replay:
        return Replay(
            format_version=REPLAY_FORMAT_VERSION,
            game_version=self._game_version,
            run=self._run,
            result=result,
            ticks=self._ticks,
        )
