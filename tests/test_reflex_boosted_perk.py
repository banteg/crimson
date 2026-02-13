from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import player_frame_dt_after_roundtrip
from crimson.math_parity import f32
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.sim.world_state import WorldState


def test_reflex_boosted_scales_dt_by_0_9_in_world_step() -> None:
    world_size = 2048.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )

    player = PlayerState(index=0, pos=Vec2())
    player.move_speed = 2.0
    player.heading = Vec2(1.0, 0.0).to_heading()
    player.perk_counts[int(PerkId.REFLEX_BOOSTED)] = 1
    world.players.append(player)

    world.step(
        1.0,
        inputs=[PlayerInput(move=Vec2(1.0, 0.0))],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert player.pos.x == pytest.approx(90.0)  # 100.0 * 0.9 (speed_multiplier=2.0, move_speed=2.0)


def test_world_step_uses_player_roundtrip_dt_for_post_player_bonus_timers() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2()))
    world.state.time_scale_active = True
    world.state.bonuses.reflex_boost = 0.75

    dt = 0.016
    expected_post_player_dt = player_frame_dt_after_roundtrip(
        dt=dt,
        time_scale_active=True,
        reflex_boost_timer=float(world.state.bonuses.reflex_boost),
    )
    expected_reflex = float(f32(float(world.state.bonuses.reflex_boost) - float(expected_post_player_dt)))
    plain_reflex = float(f32(float(world.state.bonuses.reflex_boost) - float(dt)))
    assert expected_reflex != plain_reflex

    world.step(
        dt,
        apply_world_dt_steps=False,
        inputs=[PlayerInput()],
        world_size=1024.0,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert world.state.bonuses.reflex_boost == pytest.approx(expected_reflex, abs=1e-9)
