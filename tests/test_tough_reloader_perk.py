from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_tough_reloader_halves_damage_while_reloading() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0, reload_active=True)
    player.perk_counts[int(PerkId.TOUGH_RELOADER)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1, rand=lambda: 0)

    assert_float_close(applied, 5.0)
    assert_float_close(player.health, 95.0)
