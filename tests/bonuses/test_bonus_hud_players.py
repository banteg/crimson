from __future__ import annotations

import pytest

from crimson.bonuses.apply import bonus_apply
from crimson.bonuses.hud import bonus_hud_update
from crimson.bonuses.ids import BonusId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime


@pytest.mark.parametrize("player_count", [1, 2, 3, 4])
@pytest.mark.parametrize("bonus_id", [BonusId.SHIELD, BonusId.SPEED, BonusId.FIRE_BULLETS])
def test_timed_bonus_hud_tracks_every_player_without_restarting_slide(player_count: int, bonus_id: BonusId) -> None:
    state = GameplayState()
    players = [PlayerState(index=index, pos=Vec2()) for index in range(player_count)]
    for _ in range(2):
        bonus_apply(state, players[-1], bonus_id, amount=10, origin=Vec2(), creatures=[], players=players,
                    creature_damage_runtime=RecordingCreatureDamageRuntime())
        bonus_hud_update(state, players, dt=1.0)
        slots = [slot for slot in state.bonus_hud.slots if slot.active]
        assert len(slots) == 1
        slot = slots[0]
        assert slot.slide_x == -2.0
        assert len(slot.timer_values) == player_count
        assert slot.timer_values[-1] > 0.0
        assert all(timer == 0.0 for timer in slot.timer_values[:-1])
        before_slide = slot.slide_x
        bonus_apply(state, players[-1], bonus_id, amount=10, origin=Vec2(), creatures=[], players=players,
                    creature_damage_runtime=RecordingCreatureDamageRuntime())
        assert slot.slide_x == before_slide
    for player in players:
        player.shield_timer = player.speed_bonus_timer = player.fire_bullets_timer = 0.0
    bonus_hud_update(state, players, dt=1.0)
    assert not any(slot.active for slot in state.bonus_hud.slots)
