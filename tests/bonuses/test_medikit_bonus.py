from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime


def test_medikit_narrows_updated_health_to_f32() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=58.0952262878418)

    bonus_apply(
        state,
        player,
        BonusId.MEDIKIT,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=()),
        origin=Vec2(),
        creatures=(),
        players=[player],
    )

    assert player.health == 68.09523010253906
