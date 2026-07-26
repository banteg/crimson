from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace

from crimson.sim.hooks import TickResult
from crimson.sim.sessions import QuestSpawnState
from crimson.sim.terrain_fx import TerrainFxBatch
from grim.sfx_map import SfxId
from tests.support.builders.tick_payload import make_tick_payload
from tests.support.builders.tick_result import make_tick_result


@dataclass
class FakePlaybackDriver:
    """Minimal fake driver for replay playback mode tests.

    Returns stub ``TickResult`` objects from ``step_tick``.
    """

    tick_limit: int = 0
    on_step: Callable[[], None] | None = None
    quest_spawn_state: QuestSpawnState | None = None
    post_apply_sfx: tuple[SfxId, ...] = ()
    terrain_fx: TerrainFxBatch = TerrainFxBatch()
    game_tune_started: bool = False
    elapsed_ms: float = 0.0

    @property
    def session(self) -> object:
        return SimpleNamespace(game_tune_started=bool(self.game_tune_started))

    def step_tick(self, tick_index: int) -> TickResult:
        if self.on_step is not None:
            self.on_step()
        return make_tick_result(
            tick_index=int(tick_index),
            dt_sim=1.0 / 60.0,
            payload=make_tick_payload(
                dt_sim=1.0 / 60.0,
                terrain_fx=self.terrain_fx,
                post_apply_sfx=tuple(self.post_apply_sfx),
            ),
        )
