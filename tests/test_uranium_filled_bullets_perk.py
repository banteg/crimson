from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.gameplay import PlayerState
from crimson.perks import PerkId


def test_uranium_filled_bullets_doubles_bullet_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.perk_counts[int(PerkId.URANIUM_FILLED_BULLETS)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner_id=-100,
        dt=0.016,
        players=[player],
        rand=lambda: 0,
    )

    assert killed is False
    assert creature.hp == pytest.approx(80.0)
