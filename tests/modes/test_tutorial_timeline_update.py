from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.creatures.spawn_ids import CreatureFlags, SpawnId
from crimson.game_modes import GameMode
from crimson.sim.input import PlayerInput
from crimson.sim.world_state import WorldState
from crimson.tutorial.timeline import tutorial_timeline_update
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.builders.session import make_session, make_world


def _tutorial_world() -> WorldState:
    world = make_world()
    world.state.game_mode = GameMode.TUTORIAL
    return world


def test_the_first_stage_starts_after_the_bootstrap_transition() -> None:
    world = _tutorial_world()

    tutorial_timeline_update(world, dt_ms=1000)

    assert world.state.tutorial.stage_index == 0
    assert world.state.tutorial.stage_transition_timer_ms == 0
    assert world.state.tutorial_overlay.prompt_text == "In this tutorial you'll learn how to play Crimsonland"


def test_moving_on_stage_1_seeds_three_point_bonuses() -> None:
    world = _tutorial_world()
    tutorial = world.state.tutorial
    tutorial.stage_index, tutorial.stage_transition_timer_ms = 1, -1
    tutorial.move_active_this_tick = True

    tutorial_timeline_update(world, dt_ms=16)

    assert tutorial.stage_transition_timer_ms == -1000
    assert [(b.bonus_id, b.amount, b.pos) for b in world.state.bonus_pool.iter_active()] == [
        (BonusId.POINTS, 500, Vec2(260.0, 260.0)),
        (BonusId.POINTS, 1000, Vec2(600.0, 400.0)),
        (BonusId.POINTS, 500, Vec2(300.0, 400.0)),
    ]
    assert [request.sfx_id for request in world.state.sfx_queue] == [SfxId.UI_LEVELUP]


def test_stage_5_repeats_give_the_carrier_its_bonus() -> None:
    world = _tutorial_world()
    tutorial = world.state.tutorial
    tutorial.stage_index, tutorial.stage_transition_timer_ms, tutorial.repeat_spawn_count = 5, -1, 1

    tutorial_timeline_update(world, dt_ms=16)

    assert tutorial.repeat_spawn_count == 2
    assert tutorial.hint_bonus_creature_ref is not None
    carrier = world.creatures.entries[tutorial.hint_bonus_creature_ref]
    assert carrier.pos == Vec2(1056.0, 1056.0)
    assert (carrier.bonus_id, carrier.bonus_duration_override) == (BonusId.WEAPON, 5)
    assert carrier.flags & CreatureFlags.BONUS_ON_DEATH


def test_a_dead_carrier_from_an_earlier_repeat_latches_the_next_hint_again() -> None:
    world = _tutorial_world()
    tutorial = world.state.tutorial
    carrier_index = world.creatures.spawn_template(
        SpawnId.ALIEN_BONUS_CARRIER_27, Vec2(-32.0, 1056.0), 3.1415927, state=world.state, detail_preset=5,
    )[1]
    assert carrier_index is not None
    carrier = world.creatures.entries[carrier_index]
    carrier.hp, carrier.active = 0.0, False
    tutorial.stage_index, tutorial.stage_transition_timer_ms = 5, -1000
    tutorial.hint_bonus_creature_ref, tutorial.hint_index, tutorial.hint_alpha = carrier_index, 4, 1000

    tutorial_timeline_update(world, dt_ms=16)

    # Repeats 6 and 7 spawn no carrier, so native latches on the old one: a pair spawns and the hint moves on.
    assert tutorial.hint_fade_in
    assert tutorial.hint_index == 5
    assert [c.pos for c in world.creatures.iter_active()] == [Vec2(128.0, 128.0), Vec2(152.0, 160.0)]
    # The hint fades out on the latch frame and in from the next one.
    assert tutorial.hint_alpha == 1000 - 16 * 3


def test_stage_5_experience_levels_up_in_the_same_world_step() -> None:
    session, world = make_session(game_mode=GameMode.TUTORIAL)
    tutorial = world.state.tutorial
    tutorial.stage_index, tutorial.stage_transition_timer_ms, tutorial.repeat_spawn_count = 5, -1, 7

    session.step_tick(dt=1.0 / 60.0, inputs=[PlayerInput(aim=Vec2(512.0, 512.0))])

    # `tutorial_timeline_update` runs before the level-up check, which turns the 3000 XP into a perk.
    assert world.players[0].experience == 3000
    assert world.players[0].level == 2
    assert world.state.perk_selection.pending_count == 1
