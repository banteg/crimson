from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput, PlayerState
from crimson.perks import PerkId
from crimson.sim.world_state import WorldState


def test_evil_eyes_freezes_creature_under_aim() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    player = PlayerState(index=0, pos=Vec2(300.0, 100.0))
    player.perk_counts[int(PerkId.EVIL_EYES)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.size = 50.0
    creature.move_speed = 1.0

    # `perks_update_effects` evaluates Evil Eyes before `player_update` applies
    # current-frame input aim, so seed the previous-frame aim.
    player.aim = Vec2(float(creature.pos.x), float(creature.pos.y))

    before = (float(creature.pos.x), float(creature.pos.y))
    events = world.step(
        0.5,
        inputs=[PlayerInput(aim=Vec2(float(creature.pos.x), float(creature.pos.y)))],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )
    assert events

    after = (float(creature.pos.x), float(creature.pos.y))
    assert math.isclose(after[0], before[0], abs_tol=1e-6)
    assert math.isclose(after[1], before[1], abs_tol=1e-6)
