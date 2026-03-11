from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_doctor_increases_bullet_damage_by_20_percent() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.DOCTOR)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is False
    assert_float_close(creature.hp, 88.0)
