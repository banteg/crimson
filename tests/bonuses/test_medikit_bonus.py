from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime


def test_medikit_narrows_updated_health_to_f32() -> None:
    world = make_world()
    player = world.players[0]
    player.health = 58.0952262878418

    bonus_apply(
        world.state,
        player,
        BonusId.MEDIKIT,
        amount=10,
        step_runtime=make_step_runtime(world),
        origin=Vec2(),
        creatures=world.creatures.entries,
        players=world.players,
    )

    assert player.health == 68.09523010253906
