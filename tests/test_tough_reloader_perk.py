from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage


def test_tough_reloader_halves_damage_while_reloading() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=100.0, reload_active=True)
    player.perk_counts[int(PerkId.TOUGH_RELOADER)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1, rand=lambda: 0)

    assert applied == pytest.approx(5.0)
    assert player.health == pytest.approx(95.0)
