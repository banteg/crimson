from __future__ import annotations

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

    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    player.perk_counts[int(PerkId.REFLEX_BOOSTED)] = 1
    world.players.append(player)

    world.step(
        1.0,
        inputs=[PlayerInput(move_x=1.0, move_y=0.0)],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert player.pos_x == pytest.approx(45.0)  # 50.0 * 0.9 (move_speed_multiplier=2.0)
