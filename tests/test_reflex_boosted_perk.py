from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput, PlayerState
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

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.move_speed = 2.0
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
