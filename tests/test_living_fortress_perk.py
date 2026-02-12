from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId


def test_living_fortress_scales_bullet_damage_by_stationary_timers() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)

    player0 = PlayerState(index=0, pos=Vec2())
    player0.perk_counts[int(PerkId.LIVING_FORTRESS)] = 1
    player0.living_fortress_timer = 10.0  # 1.5x

    player1 = PlayerState(index=1, pos=Vec2())
    player1.living_fortress_timer = 20.0  # 2.0x

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner_id=-100,
        dt=0.016,
        players=[player0, player1],
        rand=lambda: 0,
    )

    assert killed is False
    assert creature.hp == pytest.approx(70.0)
