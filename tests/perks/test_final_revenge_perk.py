from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE
from crimson.effects import FxQueue, FxQueueRotated
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.factories import make_creature_state, make_step_runtime, place_creatures, player_input
from tests.support.helpers import assert_float_close


def test_final_revenge_triggers_explosion_damage_on_death() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.5)
    world.state.perks[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 10000.0
    creature.max_hp = 10000.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 0.0
    creature.contact_damage = 1.0
    creature.collision_timer = 0.1

    events = world.step(
        0.2,
        inputs=[player_input()],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert_float_close(creature.hp, 7440.0)  # 10000 - (512 - 0) * 5
    assert sfx_ids(events.sfx).count(SfxId.EXPLOSION_LARGE) == 1
    assert sfx_ids(events.sfx).count(SfxId.SHOCKWAVE) == 1
    assert SfxId.EXPLOSION_LARGE in sfx_ids(events.sfx)
    assert SfxId.SHOCKWAVE in sfx_ids(events.sfx)


def test_final_revenge_triggers_from_player_update_damage_same_step() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.1, weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    world.state.perks[int(PerkId.FINAL_REVENGE)] = 1
    world.state.perks[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.experience = 100
    player.weapon.reload_active = True
    player.weapon.reload_timer = 1.0
    player.weapon.reload_timer_max = 1.0
    world.players.append(player)

    events = world.step(
        0.05,
        inputs=[player_input(fire_down=True, aim=Vec2(120.0, 100.0))],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert sfx_ids(events.sfx).count(SfxId.EXPLOSION_LARGE) == 1
    assert sfx_ids(events.sfx).count(SfxId.SHOCKWAVE) == 1


def test_final_revenge_runs_before_later_creature_slots_update() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.5)
    world.state.perks[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    attacker = world.creatures.entries[0]
    attacker.active = True
    attacker.pos = Vec2(100.0, 100.0)
    attacker.hp = 10000.0
    attacker.max_hp = 10000.0
    attacker.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    attacker.size = 48.0
    attacker.move_speed = 0.0
    attacker.contact_damage = 1.0

    later = world.creatures.entries[1]
    later.active = True
    later.pos = Vec2(100.0, 100.0)
    later.hp = 100.0
    later.max_hp = 100.0
    later.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    later.size = 48.0
    later.move_speed = 0.0
    later.attack_cooldown = 1.0

    world.step(
        0.2,
        inputs=[player_input()],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert later.hp < 0.0
    # The inline blast kills slot 1 before creature_update_all reaches it, so
    # its live-path attack-cooldown decrement does not run this frame.
    assert later.attack_cooldown == 1.0


def test_final_revenge_does_not_trigger_from_direct_death_clock_drain() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.1)
    world.state.perks[int(PerkId.DEATH_CLOCK)] = 1
    world.state.perks[int(PerkId.FINAL_REVENGE)] = 1
    world.players.append(player)

    events = world.step(
        0.05,
        inputs=[player_input()],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert player.health < 0.0
    assert SfxId.EXPLOSION_LARGE not in sfx_ids(events.sfx)
    assert SfxId.SHOCKWAVE not in sfx_ids(events.sfx)


def _die_with_final_revenge(world: WorldState, player: PlayerState) -> None:
    world.state.perks[PerkId.FINAL_REVENGE] = 1
    world.players.append(player)
    player_take_damage(make_step_runtime(world), player, 1000.0, dt=0.1)


def test_final_revenge_aoe_includes_active_non_positive_hp_entries() -> None:
    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    active_dead, active_alive, active_far = place_creatures(
        world,
        [
            make_creature_state(pos=Vec2(100.0, 100.0), hp=0.0, max_hp=10.0),
            make_creature_state(pos=Vec2(100.0, 100.0), hp=10000.0),
            make_creature_state(pos=Vec2(2000.0, 2000.0), hp=10.0),
        ],
    )[:3]

    _die_with_final_revenge(world, PlayerState(index=0, pos=Vec2(100.0, 100.0)))

    assert active_dead.hit_flash_timer > 0.0
    assert_float_close(active_alive.hp, 7440.0)  # 10000 - (512 - 0) * 5
    assert active_far.hit_flash_timer == 0.0


def test_final_revenge_damage_uses_native_pc24_arithmetic() -> None:
    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    creature = place_creatures(
        world, [make_creature_state(pos=Vec2(155.231201171875, 295.6527099609375), hp=10000.0)],
    )[0]

    _die_with_final_revenge(world, PlayerState(index=0, pos=Vec2()))

    assert creature.hp == f32(10000.0 - 890.364990234375)
    assert not world.state.bonus_spawn_guard
