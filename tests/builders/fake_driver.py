from __future__ import annotations

from dataclasses import dataclass

from builders.tick_payload import make_tick_payload
from builders.tick_result import make_tick_result

from crimson.sim.hooks import TickResult
from crimson.sim.sessions import QuestSpawnState


@dataclass
class FakePlaybackDriver:
    """Minimal fake driver for replay playback mode tests.

    Returns stub ``TickResult`` objects from ``step_tick``.
    """

    tick_limit: int = 0
    on_step: object | None = None
    quest_spawn_state: QuestSpawnState | None = None
    post_apply_sfx_keys: tuple[str, ...] = ()

    def step_tick(self, tick_index: int) -> TickResult:
        if self.on_step is not None:
            self.on_step()
        return make_tick_result(
            tick_index=int(tick_index),
            dt_sim=1.0 / 60.0,
            payload=make_tick_payload(
                dt_sim=1.0 / 60.0,
                post_apply_sfx_keys=tuple(self.post_apply_sfx_keys),
            ),
        )
