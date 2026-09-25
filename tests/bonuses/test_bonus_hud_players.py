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


def _apply(state: GameplayState, players: list[PlayerState], bonus_id: BonusId) -> None:
    bonus_apply(state, players[0], bonus_id, amount=10, origin=Vec2(), creatures=[], players=players,
                creature_damage_runtime=RecordingCreatureDamageRuntime())


def test_repickup_reverses_a_sliding_out_slot_instead_of_restarting_it() -> None:
    state = GameplayState()
    players = [PlayerState(index=0, pos=Vec2())]
    _apply(state, players, BonusId.REFLEX_BOOST)
    bonus_hud_update(state, players, dt=1.0)
    state.bonuses.reflex_boost = 0.0
    bonus_hud_update(state, players, dt=0.25)
    slot = state.bonus_hud.slots[0]
    assert slot.slide_x == -82.0

    _apply(state, players, BonusId.REFLEX_BOOST)
    assert [s.active for s in state.bonus_hud.slots[:2]] == [True, False]
    assert slot.slide_x == -82.0


def test_repickup_of_a_parked_slot_keeps_its_offscreen_position() -> None:
    state = GameplayState()
    players = [PlayerState(index=0, pos=Vec2())]
    _apply(state, players, BonusId.REFLEX_BOOST)
    _apply(state, players, BonusId.ENERGIZER)
    bonus_hud_update(state, players, dt=1.0)
    state.bonuses.reflex_boost = 0.0
    for _ in range(5):
        bonus_hud_update(state, players, dt=1.0)
    parked = state.bonus_hud.slots[0]
    assert parked.active
    assert parked.slide_x == -1602.0

    _apply(state, players, BonusId.REFLEX_BOOST)
    assert parked.slide_x == -1602.0
    assert not state.bonus_hud.slots[2].active
