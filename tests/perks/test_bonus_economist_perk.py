from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.perks import PerkId
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime


def _apply_double_experience(*, bonus_economist: bool) -> float:
    world = make_world()
    world.state.perks[int(PerkId.BONUS_ECONOMIST)] = int(bonus_economist)
    player = world.players[0]
    bonus_apply(
        world.state,
        player,
        BonusId.DOUBLE_EXPERIENCE,
        step_runtime=make_step_runtime(world),
        amount=10,
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
    )
    return world.state.bonuses.double_experience


def test_bonus_economist_extends_bonus_timers() -> None:
    assert _apply_double_experience(bonus_economist=False) == 6.0
    assert _apply_double_experience(bonus_economist=True) == 9.0
