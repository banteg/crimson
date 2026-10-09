from __future__ import annotations

import pytest

from crimson.bonuses.apply import bonus_apply
from crimson.bonuses.hud import bonus_hud_update
from crimson.bonuses.ids import BonusId
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime


def _apply(world: WorldState, player_index: int, bonus_id: BonusId) -> None:
    bonus_apply(world.state, world.players[player_index], bonus_id, amount=10, origin=Vec2(),
                creatures=world.creatures.entries, players=world.players, step_runtime=make_step_runtime(world))


@pytest.mark.parametrize("player_count", [1, 4])
@pytest.mark.parametrize("bonus_id", [BonusId.SHIELD, BonusId.SPEED, BonusId.FIRE_BULLETS])
def test_timed_bonus_hud_tracks_every_player_without_restarting_slide(player_count: int, bonus_id: BonusId) -> None:
    world = make_world(player_count=player_count)
    state, players = world.state, world.players
    for _ in range(2):
        _apply(world, -1, bonus_id)
        bonus_hud_update(state, players, dt=1.0)
        slots = [slot for slot in state.bonus_hud.slots if slot.active]
        assert len(slots) == 1
        slot = slots[0]
        assert slot.slide_x == -2.0
        assert len(slot.timer_values) == player_count
        assert slot.timer_values[-1] > 0.0
        assert all(timer == 0.0 for timer in slot.timer_values[:-1])
        before_slide = slot.slide_x
        _apply(world, -1, bonus_id)
        assert slot.slide_x == before_slide
    for player in players:
        player.shield_timer = player.speed_bonus_timer = player.fire_bullets_timer = 0.0
    bonus_hud_update(state, players, dt=1.0)
    assert not any(slot.active for slot in state.bonus_hud.slots)


def test_repickup_reverses_a_sliding_out_slot_instead_of_restarting_it() -> None:
    world = make_world()
    state, players = world.state, world.players
    _apply(world, 0, BonusId.REFLEX_BOOST)
    bonus_hud_update(state, players, dt=1.0)
    state.bonuses.reflex_boost = 0.0
    bonus_hud_update(state, players, dt=0.25)
    slot = state.bonus_hud.slots[0]
    assert slot.slide_x == -82.0

    _apply(world, 0, BonusId.REFLEX_BOOST)
    assert [s.active for s in state.bonus_hud.slots[:2]] == [True, False]
    assert slot.slide_x == -82.0


@pytest.mark.parametrize(("preserve_bugs", "parked_x"), [(True, -1602.0), (False, -185.0)])
def test_repickup_of_a_parked_slot_reverses_from_its_parked_position(preserve_bugs: bool, parked_x: float) -> None:
    world = make_world(preserve_bugs=preserve_bugs)
    state, players = world.state, world.players
    _apply(world, 0, BonusId.REFLEX_BOOST)
    _apply(world, 0, BonusId.ENERGIZER)
    bonus_hud_update(state, players, dt=1.0)
    state.bonuses.reflex_boost = 0.0
    for _ in range(5):
        bonus_hud_update(state, players, dt=1.0)
    parked = state.bonus_hud.slots[0]
    assert parked.active
    assert parked.slide_x == parked_x

    _apply(world, 0, BonusId.REFLEX_BOOST)
    assert parked.slide_x == parked_x
    assert not state.bonus_hud.slots[2].active
    bonus_hud_update(state, players, dt=0.1)
    # Visible again (right of the hidden edge) only when the parking offset was clamped.
    assert (parked.slide_x > -184.0) is not preserve_bugs
