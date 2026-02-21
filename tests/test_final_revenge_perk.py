from __future__ import annotations

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_final_revenge_triggers_explosion_damage_on_death() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.5)
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10000.0
    creature.max_hp = 10000.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.move_speed = 0.0
    creature.contact_damage = 1.0
    creature.collision_timer = 0.1

    events = world.step(
        0.2,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert_float_close(creature.hp, 7440.0)  # 10000 - (512 - 0) * 5
    assert events.sfx.count("sfx_explosion_large") == 1
    assert events.sfx.count("sfx_shockwave") == 1
    assert "sfx_explosion_large" in events.sfx
    assert "sfx_shockwave" in events.sfx


def test_final_revenge_triggers_from_player_update_damage_same_step() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.1, weapon_id=int(WeaponId.PISTOL))
    player.perk_counts[int(PerkId.FINAL_REVENGE)] = 1
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.experience = 100
    player.reload_active = True
    player.reload_timer = 1.0
    player.reload_timer_max = 1.0
    world.players.append(player)

    events = world.step(
        0.05,
        inputs=[PlayerInput(fire_down=True, aim=Vec2(120.0, 100.0))],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert events.sfx.count("sfx_explosion_large") == 1
    assert events.sfx.count("sfx_shockwave") == 1
