from __future__ import annotations

import math
from dataclasses import dataclass

import pytest

import crimson.creatures.runtime as creature_runtime
from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusEntry
from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, PHANTOM_CREATURE_INDEX, CreaturePool
from crimson.creatures.spawn import (
    HAS_SPAWN_SLOT_FLAG,
    NATIVE_SPAWN_SLOT_COUNT,
    RANDOM_HEADING_SENTINEL,
    CreatureAiMode,
    CreatureFlags,
    CreatureTypeId,
    SpawnId,
    SpawnSlot,
    creature_spawn,
    survival_spawn_creature,
)
from crimson.effects import EffectPool, FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression


def test_chain_members_link_to_the_previous_members_pool_slot() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    pool = CreaturePool()
    for i in range(5):
        pool.entries[i].active = True
        pool.entries[i].hp = 1.0

    returned = pool.spawn_template(SpawnId.FORMATION_CHAIN_ALIEN_10_13, Vec2(100.0, 200.0), 0.0, state=state, detail_preset=5)

    assert returned == 15
    assert pool.entries[5].link_index == 15
    assert [pool.entries[i].link_index for i in range(6, 16)] == list(range(5, 15))


def test_spawner_takes_the_first_ownerless_spawn_slot() -> None:
    state = GameplayState(rng=Crand(0))
    pool = CreaturePool()
    pool.entries[0].active = True
    pool.entries[0].hp = 1.0
    pool.spawn_slots[0].owner_creature = 0

    returned = pool.spawn_template(SpawnId.ZOMBIE_BOSS_SPAWNER_00, Vec2(100.0, 200.0), 0.0, state=state, detail_preset=5)

    assert returned == 1
    assert pool.entries[1].link_index == 1
    assert pool.spawn_slots[1] == SpawnSlot(
        owner_creature=1,
        timer=1.0,
        count=0,
        limit=0x32C,
        interval=x87_pc24_add(f32(0.7), f32(0.2)),
        child_template_id=SpawnId.ZOMBIE_RANDOM_41,
    )


def test_spawner_overwrites_the_last_spawn_slot_when_all_are_owned() -> None:
    state = GameplayState(rng=Crand(0))
    pool = CreaturePool()
    for owner_index, slot in enumerate(pool.spawn_slots):
        slot.owner_creature = 100 + owner_index

    returned = pool.spawn_template(SpawnId.ZOMBIE_BOSS_SPAWNER_00, Vec2(100.0, 200.0), 0.0, state=state, detail_preset=5)

    assert pool.entries[returned].link_index == NATIVE_SPAWN_SLOT_COUNT - 1
    assert pool.spawn_slots[-1].owner_creature == returned
    assert [slot.owner_creature for slot in pool.spawn_slots[:-1]] == list(range(100, 100 + NATIVE_SPAWN_SLOT_COUNT - 1))


def test_spawn_template_in_the_arena_spawns_burst_fx() -> None:
    state = GameplayState(rng=Crand(0))
    pool = CreaturePool()

    pool.spawn_template(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), 0.0, state=state, detail_preset=5)

    active = state.effects.iter_active()
    assert len(active) == 8
    assert all(int(entry.effect_id) == 0 for entry in active)


def test_hardcore_runtime_spawn_clears_shared_quest_retry_count() -> None:
    world = make_world()
    world.state.hardcore = True
    world.state.quest_fail_retry_count = 4

    world.creatures.spawn_template(
        SpawnId.ALIEN_HIDDEN_1_21,
        Vec2(100.0, 200.0),
        0.0,
        state=world.state,
        detail_preset=5,
    )

    assert world.state.quest_fail_retry_count == 0


def test_angle_approach_wraps_tau_boundary_like_native_capture() -> None:
    # Regression for Session 19 creature slot 32 drift at ticks 91->92.
    angle = -0.3199998736381531
    angle = creature_runtime._angle_approach(
        angle,
        -1.532211422920227,
        3.2,
        0.1,
    )
    assert_float_close(angle, 6.283185958862305)
    angle = creature_runtime._angle_approach(
        angle,
        -1.5394508838653564,
        3.2,
        0.1,
    )
    assert_float_close(angle, -0.3199995458126068)


def test_creature_movement_heading_subtraction_uses_native_f32_store() -> None:
    delta = creature_runtime._movement_delta_from_heading_f32(
        0.49451950192451477,
        dt=0.03400000184774399,
        move_scale=1.0,
        move_speed=1.1699999570846558,
    )

    assert delta.x == 0.566398024559021
    assert delta.y == -1.0504270792007446


def test_spawn_slot_update_uses_random_heading_sentinel(mocker) -> None:
    world = make_world()
    pool = world.creatures

    owner = pool.entries[0]
    owner.active = True
    owner.hp = 100.0
    owner.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    owner.flags = HAS_SPAWN_SLOT_FLAG
    owner.heading = 1.234
    owner.pos = Vec2(200.0, 300.0)
    owner.link_index = 0
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    pool.spawn_slots[0] = SpawnSlot(
        owner_creature=0,
        timer=0.0,
        count=0,
        limit=1,
        interval=1.0,
        child_template_id=SpawnId.ALIEN_RANDOM_1D,
    )

    spawn_template = mocker.patch.object(creature_runtime, "creature_spawn_template", return_value=1)

    step_creatures(world, 1.0 / 60.0)

    spawn_template.assert_called_once()
    _pool, child_template_id, _pos, heading = spawn_template.call_args.args
    assert child_template_id == SpawnId.ALIEN_RANDOM_1D
    assert_float_close(heading, RANDOM_HEADING_SENTINEL)
    assert spawn_template.call_args.kwargs["state"] is world.state


def test_spawn_slot_update_requires_spawner_flag() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    owner = pool.entries[0]
    owner.active = True
    owner.hp = 100.0
    owner.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    owner.flags = CreatureFlags(0)
    owner.ai_mode = CreatureAiMode.ORBIT_PLAYER
    owner.move_speed = 0.0
    owner.size = 45.0
    owner.pos = Vec2(256.0, 256.0)
    owner.link_index = 0

    pool.spawn_slots[0] = SpawnSlot(
        owner_creature=0,
        timer=0.0,
        count=0,
        limit=1,
        interval=1.0,
        child_template_id=SpawnId.ALIEN_RANDOM_1D,
    )

    step_creatures(world, 1.0 / 60.0)

    assert pool.spawn_slots[0].count == 0
    assert_float_close(pool.spawn_slots[0].timer, 0.0)
    assert [idx for idx, creature in enumerate(pool.entries) if idx != 0 and creature.active] == []


def test_spawn_slot_child_can_update_in_same_tick() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(640.0, 700.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    owner = pool.entries[0]
    owner.active = True
    owner.hp = 100.0
    owner.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    owner.pos = Vec2(256.0, 256.0)
    owner.flags = HAS_SPAWN_SLOT_FLAG
    owner.ai_mode = CreatureAiMode.ORBIT_PLAYER
    owner.move_speed = 0.0
    owner.size = 45.0
    owner.link_index = 0

    pool.spawn_slots[0] = SpawnSlot(
        owner_creature=0,
        timer=0.0,
        count=0,
        limit=1,
        interval=1.0,
        child_template_id=SpawnId.ALIEN_BIG_GRAY_29,
    )

    step_creatures(world, 1.0 / 60.0)

    child_indices = [idx for idx, creature in enumerate(pool.entries) if idx != 0 and creature.active]
    assert child_indices
    child = pool.entries[child_indices[0]]
    assert child.target_heading is not None
    assert abs(float(child.target_heading)) > 1e-6
    assert child.pos != Vec2(256.0, 256.0)


def test_non_spawner_update_does_not_clamp_offscreen_positions() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(-64.0, 1088.0)

    step_creatures(world, 1.0 / 60.0)

    assert_float_close(creature.pos.x, -64.0)
    assert_float_close(creature.pos.y, 1088.0)


def test_attack_cooldown_is_stored_at_native_precision() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(128.0, 128.0)
    creature.attack_cooldown = 1.0

    step_creatures(world, 0.1)
    step_creatures(world, 0.1)

    expected = f32(f32(1.0 - f32(0.1)) - f32(0.1))
    assert creature.attack_cooldown == expected


def test_non_spawner_movement_is_independent_of_creature_type_id() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    pool = world.creatures

    start_pos = Vec2(120.0, 160.0)
    for idx, type_id in enumerate((CreatureTypeId.ZOMBIE, CreatureTypeId.SPIDER_SP2)):
        creature = pool.entries[idx]
        creature.active = True
        creature.type_id = type_id
        creature.hp = 50.0
        creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
        creature.flags = CreatureFlags(0)
        creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
        creature.move_speed = 2.0
        creature.size = 45.0
        creature.pos = start_pos
        creature.contact_damage = 0.0

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    base = pool.entries[0]
    variant = pool.entries[1]
    base_delta = base.pos - start_pos
    variant_delta = variant.pos - start_pos

    assert_float_close(variant_delta.x, base_delta.x)
    assert_float_close(variant_delta.y, base_delta.y)
    assert_float_close(variant.vel.x, base.vel.x)
    assert_float_close(variant.vel.y, base.vel.y)


def test_ai_mode5_near_link_scales_runtime_movement_delta() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(900.0, 900.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    pool = world.creatures

    link = pool.entries[0]
    link.active = True
    link.type_id = CreatureTypeId.ZOMBIE
    link.hp = 100.0
    link.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    link.flags = CreatureFlags(0)
    link.ai_mode = CreatureAiMode.ORBIT_PLAYER
    link.move_speed = 0.0
    link.size = 45.0
    link.pos = Vec2(100.0, 100.0)

    near = pool.entries[1]
    near.active = True
    near.type_id = CreatureTypeId.ZOMBIE
    near.hp = 100.0
    near.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    near.flags = CreatureFlags(0)
    near.ai_mode = CreatureAiMode.FOLLOW_LINK_TETHERED
    near.link_index = 0
    near.target_offset = Vec2()
    near.move_speed = 2.0
    near.size = 45.0
    near.pos = Vec2(100.0, 50.0)  # dist to link = 50 -> local_scale = 50 / 64
    near.contact_damage = 0.0

    far = pool.entries[2]
    far.active = True
    far.type_id = CreatureTypeId.ZOMBIE
    far.hp = 100.0
    far.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    far.flags = CreatureFlags(0)
    far.ai_mode = CreatureAiMode.FOLLOW_LINK_TETHERED
    far.link_index = 0
    far.target_offset = Vec2()
    far.move_speed = 2.0
    far.size = 45.0
    far.pos = Vec2(100.0, 20.0)  # dist to link = 80 -> local_scale = 1.0
    far.contact_damage = 0.0

    near_start = near.pos
    far_start = far.pos
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    near_step = (near.pos - near_start).length()
    far_step = (far.pos - far_start).length()

    assert near_step < far_step
    assert_float_close(far_step, 0.9999993146409377)
    assert_float_close(near_step, 0.7812510393925548)


def test_creature_contact_damage_targets_player1_when_player0_is_dead() -> None:
    world = make_world(player_count=2)
    state = world.state
    pool = world.creatures
    rng = RecordingCrand(Crand(0x1234))

    player0 = world.players[0]
    player0.pos = Vec2(100.0, 100.0)
    player0.health = 0.0
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(110.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(110.0, 100.0)

    state.rng = rng
    step_creatures(world, 1.0 / 60.0)

    assert creature.target_player == 1
    assert_float_close(player0.health, 0.0)
    assert_float_close(player1.health, 90.0)
    assert [record.caller for record in rng.records_since() if record.caller is not None][:1] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_CONTACT_SFX,
    ]


def test_near_player_movement_rollback_is_stored_at_native_precision() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 1.3
    creature.size = 45.0
    creature.pos = Vec2(110.0, 100.0)
    creature.target_player = 0

    step_creatures(world, 0.1)

    assert creature.pos.x == f32(creature.pos.x)
    assert creature.pos.y == f32(creature.pos.y)


def test_contact_cooldown_addition_is_stored_at_native_precision() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(100.0, 100.0)
    creature.attack_cooldown = f32(0.077)

    dt = f32(0.084)
    step_creatures(world, dt)

    expected = x87_pc24_add(x87_pc24_sub(f32(0.077), dt), f32(1.0))
    assert creature.attack_cooldown == expected


def test_creature_eat_gate_uses_stored_native_distance() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2()
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.orbit_radius = 1.0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 0.0
    creature.pos = Vec2(19.999998092651367, 0.003907000180333853)
    creature.vel = Vec2(1.0, 2.0)

    assert Vec2.distance_sq(creature.pos, player.pos) < 20.0 * 20.0
    assert x87_pc24_hypot(creature.pos.x, creature.pos.y) == 20.0

    step_creatures(world, 0.01)

    assert creature.pos == Vec2(19.999998092651367, 0.003907000180333853)


def test_creature_contact_gate_uses_stored_native_distance() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2()
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.orbit_radius = 1.0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.pos = Vec2(29.999998092651367, 0.009569000452756882)

    assert Vec2.distance_sq(creature.pos, player.pos) < 30.0 * 30.0
    assert x87_pc24_hypot(creature.pos.x, creature.pos.y) == 30.0

    step_runtime = step_creatures(world, 0.01)

    assert player.health == 100.0
    assert creature.attack_cooldown == 0.0
    assert sfx_ids(step_runtime.sfx) == []


def test_plague_kill_uses_exact_native_attack_sfx_caller() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.ZOMBIE
    creature.hp = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 0.0
    creature.plague_infected = True
    creature.collision_timer = 0.0
    creature.pos = Vec2(400.0, 400.0)

    state.rng = rng
    step_runtime = step_creatures(world, 1.0 / 60.0)

    assert sfx_ids(step_runtime.sfx) == [
        SfxId.ZOMBIE_ATTACK_01,
    ]
    # The bonus drop gate in the death handler draws from the same world rng first.
    assert [record.caller for record in rng.records_since() if record.caller is not None] == [
        RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BASE_GATE,
        RngCallerStatic.CREATURE_UPDATE_ALL_PLAGUE_KILL_SFX,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
    ]


def test_plague_infection_timer_keeps_native_stored_cadence() -> None:
    world = make_world()
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(500.0, 500.0)
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.orbit_radius = 1.0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(100.0, 100.0)
    creature.plague_infected = True
    creature.collision_timer = 0.0

    for _ in range(25):
        step_creatures(world, 0.02)

    assert creature.hp == 70.0
    assert creature.collision_timer == 0.49999991059303284


def test_radioactive_timer_keeps_native_stored_cadence() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2()
    state.perks[int(PerkId.RADIOACTIVE)] = 1
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.orbit_radius = 1.0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(90.0, 0.0)
    creature.collision_timer = 0.0

    for _ in range(41):
        step_creatures(world, 1.0 / 120.0)

    assert creature.hp == 97.0
    assert creature.collision_timer == 1.8440186977386475e-07


def test_single_player_dead_player_uses_dead_target_position() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures

    dead_player = world.players[0]
    dead_player.pos = Vec2(660.0, 520.0)
    dead_player.health = 0.0
    dead_player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 0.0
    creature.target_player = 0
    creature.pos = Vec2(500.0, 500.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    expected_dead_target = Vec2(1024.0 * (27.0 / 64.0), 1024.0 * (27.0 / 64.0))
    assert creature.target_player == 1
    assert creature.target == Vec2(569.058349609375, expected_dead_target.y)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert creature.target == Vec2(513.7415771484375, expected_dead_target.y)


def test_single_player_dead_player_contact_path_keeps_dead_player_undamaged() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures

    dead_player = world.players[0]
    dead_player.pos = Vec2(400.0, 400.0)
    dead_player.health = 0.0
    dead_player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(432.0, 432.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    expected_dead_target = Vec2(1024.0 * (27.0 / 64.0), 1024.0 * (27.0 / 64.0))
    assert creature.target_player == 1
    assert creature.target == expected_dead_target
    assert creature.attack_cooldown == 1.0
    assert_float_close(dead_player.health, 0.0)


def test_creature_retargets_to_closer_player1_in_two_player_mode() -> None:
    world = make_world(player_count=2)
    state = world.state
    pool = world.creatures

    player0 = world.players[0]
    player0.pos = Vec2(100.0, 100.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(104.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(104.0, 100.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert creature.target_player == 1
    assert_float_close(player0.health, 100.0)
    assert_float_close(player1.health, 90.0)


def test_creature_retarget_keeps_current_player_when_native_distances_round_equal() -> None:
    pool = CreaturePool()
    pool._update_tick = 1
    creature = pool.entries[0]
    creature.target_player = 0
    creature.pos = Vec2(0.0, 0.0)

    players = [
        PlayerState(index=0, pos=Vec2(f32(100.00000762939453), 100.0), health=100.0),
        PlayerState(index=1, pos=Vec2(100.0, 100.0), health=100.0),
    ]

    current_exact_sq = Vec2.distance_sq(creature.pos, players[0].pos)
    alternate_exact_sq = Vec2.distance_sq(creature.pos, players[1].pos)
    assert alternate_exact_sq < current_exact_sq
    assert x87_pc24_hypot(players[0].pos.x, players[0].pos.y) == x87_pc24_hypot(
        players[1].pos.x,
        players[1].pos.y,
    )
    resolution = pool._resolve_target_player(creature, players)
    assert resolution.target_player == 0
    assert creature.target_player == 0


def test_creature_update_tracks_nearest_auto_target_for_target_player() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    far = pool.entries[0]
    far.active = True
    far.hp = 50.0
    far.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    far.flags = CreatureFlags(0)
    far.ai_mode = CreatureAiMode.ORBIT_PLAYER
    far.move_speed = 0.0
    far.size = 45.0
    far.contact_damage = 0.0
    far.target_player = 0
    far.pos = Vec2(220.0, 100.0)

    near = pool.entries[1]
    near.active = True
    near.hp = 50.0
    near.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    near.flags = CreatureFlags(0)
    near.ai_mode = CreatureAiMode.ORBIT_PLAYER
    near.move_speed = 0.0
    near.size = 45.0
    near.contact_damage = 0.0
    near.target_player = 0
    near.pos = Vec2(120.0, 100.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player.auto_target == 1


def test_creature_update_auto_target_falls_back_when_previous_target_is_dead() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    dead_target = pool.entries[0]
    dead_target.active = True
    dead_target.hp = 0.0
    dead_target.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    dead_target.flags = CreatureFlags(0)
    dead_target.ai_mode = CreatureAiMode.ORBIT_PLAYER
    dead_target.move_speed = 0.0
    dead_target.size = 45.0
    dead_target.contact_damage = 0.0
    dead_target.target_player = 0
    dead_target.pos = Vec2(180.0, 100.0)

    live_target = pool.entries[1]
    live_target.active = True
    live_target.hp = 50.0
    live_target.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    live_target.flags = CreatureFlags(0)
    live_target.ai_mode = CreatureAiMode.ORBIT_PLAYER
    live_target.move_speed = 0.0
    live_target.size = 45.0
    live_target.contact_damage = 0.0
    live_target.target_player = 0
    live_target.pos = Vec2(120.0, 100.0)

    player.auto_target = 0
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player.auto_target == 1


def test_creature_auto_target_keeps_current_slot_when_native_distances_round_equal() -> None:
    pool = CreaturePool()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=100.0, auto_target=0)

    current = pool.entries[0]
    current.pos = Vec2(f32(100.00000762939453), 100.0)
    candidate = pool.entries[1]
    candidate.pos = Vec2(100.0, 100.0)

    current_exact_sq = Vec2.distance_sq(player.pos, current.pos)
    candidate_exact_sq = Vec2.distance_sq(player.pos, candidate.pos)
    assert candidate_exact_sq < current_exact_sq
    assert x87_pc24_hypot(current.pos.x, current.pos.y) == x87_pc24_hypot(
        candidate.pos.x,
        candidate.pos.y,
    )

    pool._update_player_auto_target(
        players=[player],
        preserve_bugs=True,
        player_index=0,
        creature_index=1,
        creature=candidate,
    )

    assert player.auto_target == 0


def test_creature_update_auto_target_skips_refresh_on_0x46_boundary_tick() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    far = pool.entries[0]
    far.active = True
    far.hp = 50.0
    far.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    far.flags = CreatureFlags(0)
    far.ai_mode = CreatureAiMode.ORBIT_PLAYER
    far.move_speed = 0.0
    far.size = 45.0
    far.contact_damage = 0.0
    far.target_player = 0
    far.pos = Vec2(220.0, 100.0)

    near = pool.entries[1]
    near.active = True
    near.hp = 50.0
    near.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    near.flags = CreatureFlags(0)
    near.ai_mode = CreatureAiMode.ORBIT_PLAYER
    near.move_speed = 0.0
    near.size = 45.0
    near.contact_damage = 0.0
    near.target_player = 0
    near.pos = Vec2(120.0, 100.0)

    player.auto_target = 0
    pool._update_tick = creature_runtime._TARGET_REEVAL_PERIOD - 1

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)
    assert pool._update_tick == creature_runtime._TARGET_REEVAL_PERIOD
    assert player.auto_target == 0

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)
    assert player.auto_target == 1


def test_creature_update_coop_auto_target_uses_target_player_position_by_default() -> None:
    world = make_world(player_count=2)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    current = pool.entries[0]
    current.active = True
    current.hp = 50.0
    current.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    current.flags = CreatureFlags(0)
    current.ai_mode = CreatureAiMode.ORBIT_PLAYER
    current.move_speed = 0.0
    current.size = 45.0
    current.contact_damage = 0.0
    current.target_player = 0
    current.pos = Vec2(10.0, 0.0)

    nearer_for_player1 = pool.entries[1]
    nearer_for_player1.active = True
    nearer_for_player1.hp = 50.0
    nearer_for_player1.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    nearer_for_player1.flags = CreatureFlags(0)
    nearer_for_player1.ai_mode = CreatureAiMode.ORBIT_PLAYER
    nearer_for_player1.move_speed = 0.0
    nearer_for_player1.size = 45.0
    nearer_for_player1.contact_damage = 0.0
    nearer_for_player1.target_player = 0
    nearer_for_player1.pos = Vec2(80.0, 0.0)

    player1.auto_target = 0
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player1.auto_target == 1


def test_creature_update_coop_auto_target_preserve_bugs_keeps_player1_distance_bias() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    current = pool.entries[0]
    current.active = True
    current.hp = 50.0
    current.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    current.flags = CreatureFlags(0)
    current.ai_mode = CreatureAiMode.ORBIT_PLAYER
    current.move_speed = 0.0
    current.size = 45.0
    current.contact_damage = 0.0
    current.target_player = 0
    current.pos = Vec2(10.0, 0.0)

    nearer_for_player1 = pool.entries[1]
    nearer_for_player1.active = True
    nearer_for_player1.hp = 50.0
    nearer_for_player1.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    nearer_for_player1.flags = CreatureFlags(0)
    nearer_for_player1.ai_mode = CreatureAiMode.ORBIT_PLAYER
    nearer_for_player1.move_speed = 0.0
    nearer_for_player1.size = 45.0
    nearer_for_player1.contact_damage = 0.0
    nearer_for_player1.target_player = 0
    nearer_for_player1.pos = Vec2(80.0, 0.0)

    player1.auto_target = 0
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player1.auto_target == 0


def test_creature_update_coop_auto_target_preserve_bugs_reuses_other_player_distance() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.auto_target = 0
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)

    current = pool.entries[0]
    current.active = True
    current.hp = 50.0
    current.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    current.ai_mode = CreatureAiMode.ORBIT_PLAYER
    current.move_speed = 0.0
    current.size = 45.0
    current.target_player = 0
    current.pos = Vec2(50.0, 0.0)

    candidate = pool.entries[1]
    candidate.active = True
    candidate.hp = 50.0
    candidate.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    candidate.ai_mode = CreatureAiMode.ORBIT_PLAYER
    candidate.move_speed = 0.0
    candidate.size = 45.0
    candidate.target_player = 0
    candidate.pos = Vec2(10.0, 0.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    # The candidate is 10 units from player 1, but native reuses its 90-unit
    # distance from player 2. It therefore does not replace the 50-unit slot.
    assert player0.auto_target == 0


def test_creature_update_preserve_bugs_updates_dead_auto_target_before_redirect() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    pool = world.creatures
    player0 = world.players[0]
    player0.pos = Vec2(0.0, 0.0)
    player0.health = 0.0
    player0.auto_target = 0
    player1 = world.players[1]
    player1.pos = Vec2(100.0, 0.0)
    player1.auto_target = 0

    stale_current = pool.entries[0]
    stale_current.pos = Vec2(200.0, 0.0)

    candidate = pool.entries[1]
    candidate.active = True
    candidate.hp = 50.0
    candidate.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    candidate.ai_mode = CreatureAiMode.ORBIT_PLAYER
    candidate.move_speed = 0.0
    candidate.size = 45.0
    candidate.target_player = 0
    candidate.pos = Vec2(10.0, 0.0)

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    assert player0.auto_target == 1
    assert player1.auto_target == 0
    assert candidate.target_player == 1


def test_small_creature_dies_on_contact() -> None:
    world = make_world()
    state = world.state
    pool = world.creatures

    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 30.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(120.0, 100.0)  # dist=20

    dt = 1.0 / 60.0
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, dt)

    assert_float_close(player.health, 90.0)
    assert_float_close(creature.hp, 0.0)
    assert_float_close(creature.lifecycle_stage, f32(float(CREATURE_LIFECYCLE_ALIVE) - float(dt)))
    assert pool.kill_count == 0


@dataclass
class _StubRand:
    values: list[int]

    def __post_init__(self) -> None:
        self._idx = 0
        self._state = 0

    @property
    def state(self) -> int:
        return int(self._state)

    def srand(self, seed: int) -> None:
        self._state = int(seed)
        self._idx = 0

    def _next(self) -> int:
        if self._idx >= len(self.values):
            value = 0
        else:
            value = int(self.values[self._idx])
        self._idx += 1
        self._state = int(value) & 0xFFFFFFFF
        return value

    def rand(self) -> int:
        return self._next()

    def rand_tagged(self, caller: int) -> int:
        _ = caller
        return self._next()

    def advance(self, draws: int) -> None:
        steps = int(draws)
        if steps < 0:
            raise ValueError(f"draws must be >= 0, got {draws}")
        for _ in range(steps):
            self.rand()


def test_death_awards_xp_and_can_spawn_bonus() -> None:
    state = GameplayState()
    # RNG values:
    # - try_spawn_on_kill gate: (rand % 9) == 1
    # - bonus_pick_random_type roll: roll=1 => points
    # - points amount: (rand & 7) < 3 => 1000
    stub_rand = _StubRand([1, 0, 0])
    state.rng = stub_rand

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.reward_value = 10.0
    creature.hp = 0.0

    death = pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=None,
    )
    assert death.xp_awarded == 10
    assert player.experience == 10
    assert any(entry.bonus_id != BonusId.UNUSED for entry in state.bonus_pool.entries)
    assert len(state.effects.iter_active()) == 16
    # Successful spawn-on-kill emits a 16-particle burst (4 RNG draws each).
    assert stub_rand._idx == 67


def test_every_kill_credits_player_one() -> None:
    # Native `creature_handle_death` adds the XP to player one, whoever landed the hit.
    state = GameplayState()
    state.bonus_spawn_guard = True
    players = [
        PlayerState(index=0, pos=Vec2()),
        PlayerState(index=1, pos=Vec2()),
    ]
    state.perks[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1
    pool = CreaturePool()
    pool.entries[0].active = True
    pool.entries[0].hp = 0.0
    pool.entries[0].reward_value = 10.0

    death = pool.handle_death(
        0,
        state=state,
        players=players,
        rng=state.rng,
        fx_queue=None,
    )

    assert death.xp_awarded == 13
    assert (players[0].experience, players[1].experience) == (13, 0)


def test_bonus_on_death_does_not_synthesize_burst_from_mocked_try_spawn_result(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.BONUS_ON_DEATH
    creature.bonus_id = BonusId.POINTS
    creature.bonus_duration_override = 5
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 0.0

    spawn_at = mocker.patch.object(
        state.bonus_pool,
        "spawn_at",
        return_value=BonusEntry(
            bonus_id=BonusId.POINTS,
            pos=Vec2(100.0, 100.0),
            time_left=10.0,
            time_max=10.0,
            amount=5,
        ),
    )
    try_spawn_on_kill = mocker.patch.object(
        state.bonus_pool,
        "try_spawn_on_kill",
        return_value=BonusEntry(
            bonus_id=BonusId.ENERGIZER,
            pos=Vec2(200.0, 200.0),
            time_left=10.0,
            time_max=10.0,
            amount=1,
        ),
    )

    pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=None,
    )

    spawn_at.assert_called_once()
    try_spawn_on_kill.assert_called_once()
    assert state.effects.iter_active() == []


def test_bonus_on_death_forced_drop_does_not_emit_burst_when_try_spawn_fails(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.BONUS_ON_DEATH
    creature.bonus_id = BonusId.POINTS
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 0.0

    spawn_at = mocker.patch.object(
        state.bonus_pool,
        "spawn_at",
        return_value=BonusEntry(
            bonus_id=BonusId.POINTS,
            pos=Vec2(100.0, 100.0),
            time_left=10.0,
            time_max=10.0,
            amount=5,
        ),
    )
    try_spawn_on_kill = mocker.patch.object(state.bonus_pool, "try_spawn_on_kill", return_value=None)

    pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=None,
    )

    spawn_at.assert_called_once()
    try_spawn_on_kill.assert_called_once()
    assert state.effects.iter_active() == []


def test_handle_death_shock_flag_has_no_resolved_death_sfx_without_spawning_debris() -> None:
    state = GameplayState()
    stub_rand = _StubRand([0] * 20)
    state.rng = stub_rand
    # Kill drops are out of scope here; the guard skips them before any draw.
    state.bonus_spawn_guard = True
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 0.0

    pool.handle_death(
        0,
        state=state,
        players=[PlayerState(index=0, pos=Vec2())],
        rng=state.rng,
        fx_queue=None,
    )

    assert state.effects.iter_active() == []
    assert stub_rand._idx == 0


def test_death_award_uses_float32_sum_before_truncation() -> None:
    state = GameplayState()
    state.rng = _StubRand([0])

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player.experience = 48_841
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.reward_value = 60.998285714285714
    creature.hp = 0.0

    death = pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=None,
    )
    assert death.xp_awarded == 61
    assert player.experience == 48_902


def test_handle_death_no_freeze_does_not_enqueue_fx_queue_random(mocker) -> None:
    state = GameplayState()
    state.game_mode = GameMode.RUSH
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 0.0
    creature.pos = Vec2(100.0, 100.0)

    fx_queue = FxQueue()
    add_random = mocker.patch.object(fx_queue, "add_random", wraps=fx_queue.add_random)

    pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=fx_queue,
    )

    add_random.assert_not_called()


def test_handle_death_freeze_enqueues_fx_queue_random_once(mocker) -> None:
    state = GameplayState()
    state.game_mode = GameMode.RUSH
    state.bonuses.freeze = 1.0
    state.rng = RecordingCrand(Crand(0x1234))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 0.0
    creature.pos = Vec2(100.0, 100.0)

    fx_queue = FxQueue()
    add_random = mocker.patch.object(fx_queue, "add_random", wraps=fx_queue.add_random)

    pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=fx_queue,
    )

    add_random.assert_called_once()
    tagged_callers = [
        record.caller
        for record in state.rng.records_since()
        if record.caller
        in {
            RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHARD_ANGLE,
            RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHATTER_ANGLE,
        }
    ]
    assert tagged_callers == [
        RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHARD_ANGLE,
    ] * 8 + [
        RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHATTER_ANGLE,
    ]


def test_handle_death_inactive_entry_skips_reentrant_side_effects(mocker) -> None:
    state = GameplayState()
    state.game_mode = GameMode.RUSH
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = False
    creature.hp = -1.0
    creature.reward_value = 49.0
    creature.pos = Vec2(100.0, 100.0)

    fx_queue = FxQueue()
    add_random = mocker.patch.object(fx_queue, "add_random", wraps=fx_queue.add_random)

    death = pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        fx_queue=fx_queue,
    )

    assert death.xp_awarded == 0
    assert player.experience == 0
    add_random.assert_not_called()
    assert not any(entry.bonus_id != BonusId.UNUSED for entry in state.bonus_pool.entries)


def test_handle_death_inactive_entry_forced_bonus_on_death_is_one_shot_by_default(mocker) -> None:
    state = GameplayState()
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = False
    creature.flags = CreatureFlags.BONUS_ON_DEATH
    creature.bonus_id = BonusId.POINTS
    creature.bonus_duration_override = 5
    creature.hp = -1.0
    creature.pos = Vec2(100.0, 100.0)

    spawn_at = mocker.patch.object(
        state.bonus_pool,
        "spawn_at",
        return_value=BonusEntry(
            bonus_id=BonusId.POINTS,
            pos=Vec2(100.0, 100.0),
            time_left=10.0,
            time_max=10.0,
            amount=5,
        ),
    )

    death = pool.handle_death(
        0,
        state=state,
        players=[PlayerState(index=0, pos=Vec2())],
        rng=state.rng,
        fx_queue=None,
    )
    pool.handle_death(
        0,
        state=state,
        players=[PlayerState(index=0, pos=Vec2())],
        rng=state.rng,
        fx_queue=None,
    )

    spawn_at.assert_called_once()
    assert death.xp_awarded == 0
    assert creature.bonus_id is None
    assert creature.bonus_duration_override is None


def test_handle_death_inactive_entry_forced_bonus_on_death_repeats_with_preserve_bugs(mocker) -> None:
    state = GameplayState(preserve_bugs=True)
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = False
    creature.flags = CreatureFlags.BONUS_ON_DEATH
    creature.bonus_id = BonusId.POINTS
    creature.bonus_duration_override = 5
    creature.hp = -1.0
    creature.pos = Vec2(100.0, 100.0)

    spawn_at = mocker.patch.object(
        state.bonus_pool,
        "spawn_at",
        return_value=BonusEntry(
            bonus_id=BonusId.POINTS,
            pos=Vec2(100.0, 100.0),
            time_left=10.0,
            time_max=10.0,
            amount=5,
        ),
    )

    pool.handle_death(
        0,
        state=state,
        players=[PlayerState(index=0, pos=Vec2())],
        rng=state.rng,
        fx_queue=None,
    )
    pool.handle_death(
        0,
        state=state,
        players=[PlayerState(index=0, pos=Vec2())],
        rng=state.rng,
        fx_queue=None,
    )

    assert spawn_at.call_count == 2


def test_survival_spawn_resets_the_fields_native_writes_and_keeps_the_rest() -> None:
    pool = CreaturePool()
    stale = pool.entries[0]
    stale.vel = Vec2(3.0, 4.0)
    stale.force_target = 1
    stale.attack_cooldown = 0.7
    stale.collision_timer = 0.3
    stale.anim_phase = 5.0
    stale.hit_flash_timer = 0.1
    stale.link_index = -7
    stale.target_heading = 2.5632283687591553
    stale.target = Vec2(7.0, 8.0)
    stale.target_offset = Vec2(-70.71066284179688, -70.710693359375)

    idx = survival_spawn_creature(pool, Vec2(100.0, 200.0), Crand(1), player_experience=0)

    assert idx == 0
    entry = pool.entries[0]
    assert entry.active is True
    assert entry.vel == Vec2()
    assert entry.force_target == 0
    assert entry.attack_cooldown == 0.0
    assert entry.collision_timer == 0.0
    assert entry.anim_phase == 0.0
    assert entry.hit_flash_timer == 0.1
    assert entry.link_index == -7
    assert entry.target_heading == 2.5632283687591553
    assert entry.target == Vec2(7.0, 8.0)
    assert entry.target_offset == Vec2(-70.71066284179688, -70.710693359375)


def test_spawn_template_preserves_stale_ranged_orbit_fields() -> None:
    world = make_world()
    pool = world.creatures
    pool.entries[0].orbit_angle = 0.4
    pool.entries[0].orbit_radius = float(ProjectileTemplateId.SPIDER_PLASMA)

    returned = pool.spawn_template(
        SpawnId.SPIDER_SP2_RANGED_VARIANT_37,
        Vec2(100.0, 200.0),
        0.0,
        state=world.state,
        detail_preset=5,
    )

    assert returned == 0
    assert_float_close(pool.entries[0].orbit_angle, 0.4)
    assert pool.entries[0].orbit_radius == float(ProjectileTemplateId.SPIDER_PLASMA)


def test_tick_dead_defers_corpse_deactivation_until_post_render_cleanup() -> None:
    pool = CreaturePool()
    corpse = pool.entries[6]
    corpse.active = True
    corpse.hp = -231.675
    corpse.lifecycle_stage = -9.656
    corpse.pos = Vec2(588.6516, 379.7685)
    corpse.flags = CreatureFlags.AI7_LINK_TIMER

    pool._tick_dead(
        corpse,
        dt=0.018,
        fx_queue_rotated=FxQueueRotated(),
        rng=Crand(0),
        effects=EffectPool(),
        detail_preset=5,
        violence_disabled=0,
    )

    assert corpse.active is True
    assert_float_close(corpse.lifecycle_stage, f32(-10.016))

    pool.finalize_post_render_lifecycle()
    assert corpse.active is False


def test_tick_dead_ping_pong_corpse_emits_native_19_blood_burst_rng_budget() -> None:
    effects = EffectPool()
    pool = CreaturePool()
    corpse = pool.entries[0]
    corpse.active = True
    corpse.hp = -5.0
    corpse.lifecycle_stage = 1.0
    corpse.pos = Vec2(320.0, 240.0)
    corpse.flags = CreatureFlags.ANIM_PING_PONG
    corpse.size = 24.0

    fx_queue_rotated = FxQueueRotated()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    pool._tick_dead(
        corpse,
        dt=0.1,
        fx_queue_rotated=fx_queue_rotated,
        rng=rng,
        effects=effects,
        detail_preset=5,
        violence_disabled=0,
    )

    # Native branch: 19 angle draws + 19 calls to effect_spawn_blood_splatter
    # (10 draws each in our parity model) = 209 total.
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=209,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 209
    assert [
        record.caller
        for record in rng.records_since(before_calls)
        if record.caller
        in {
            RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_8_ANGLE,
            RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_6_ANGLE,
            RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_5_ANGLE,
        }
    ] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_8_ANGLE,
    ] * 8 + [
        RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_6_ANGLE,
    ] * 6 + [
        RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_5_ANGLE,
    ] * 5
    assert len(effects.iter_active()) == 38
    # The corpse decal is queued before the burst and draws no RNG.
    assert fx_queue_rotated.count == 1


def test_dead_self_damage_tick_flags_still_reduce_lifecycle_before_dead_decay() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    corpse = pool.entries[42]
    corpse.active = True
    corpse.hp = -0.08500146865844727
    corpse.lifecycle_stage = 12.640003204345703
    corpse.flags = CreatureFlags.SELF_DAMAGE_TICK

    # Exercise a non-round frame time at the native damage boundary.
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 0.03800000250339508)

    # Native applies SELF_DAMAGE_TICK via creature_apply_damage even while hp<=0.
    assert_float_close(corpse.lifecycle_stage, f32(11.006003))


def test_newly_dead_self_damage_tick_preserves_native_prologue_order() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    corpse = pool.entries[42]
    corpse.active = True
    corpse.hp = -1.0
    corpse.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    corpse.flags = CreatureFlags.SELF_DAMAGE_TICK

    dt = f32(0.03800000250339508)
    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, dt)

    expected = x87_pc24_sub(
        x87_pc24_sub(
            x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, dt),
            x87_pc24_mul(dt, 15.0),
        ),
        x87_pc24_mul(dt, 28.0),
    )
    assert corpse.lifecycle_stage == expected


def test_live_self_damage_product_is_stored_at_native_precision() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 8.0
    creature.max_hp = 8.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags.SELF_DAMAGE_TICK
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(128.0, 128.0)

    dt = f32(0.09800000488758087)
    step_creatures(world, dt)

    expected = f32(8.0 - f32(dt * 60.0))
    assert creature.hp == expected


def test_tick_dead_death_slide_preserves_native_multiply_order() -> None:
    pool = CreaturePool()
    corpse = pool.entries[4]
    corpse.active = True
    corpse.hp = -42.440147399902344
    corpse.lifecycle_stage = 15.908000946044922
    corpse.heading = 6.330781936645508

    pool._tick_dead(
        corpse,
        dt=0.05900000408291817,
        fx_queue_rotated=FxQueueRotated(),
        rng=Crand(0),
        effects=EffectPool(),
        detail_preset=5,
        violence_disabled=0,
    )

    assert corpse.lifecycle_stage == 14.256000518798828
    assert corpse.vel == Vec2(0.3601662218570709, -7.56136417388916)


def test_spawn_allocation_uses_slot_still_active_until_post_render_cleanup() -> None:
    pool = CreaturePool()
    for idx in range(22):
        entry = pool.entries[idx]
        entry.active = True
        entry.hp = 1.0
        entry.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
        entry.pos = Vec2(float(idx), 0.0)

    corpse = pool.entries[6]
    corpse.hp = -231.675
    corpse.lifecycle_stage = -9.656
    corpse.pos = Vec2(588.6516, 379.7685)
    corpse.flags = CreatureFlags.AI7_LINK_TIMER

    pool.entries[22].active = False
    pool.entries[22].lifecycle_stage = -10.21
    pool.entries[22].hp = -45.9623

    pool._tick_dead(
        corpse,
        dt=0.018,
        fx_queue_rotated=FxQueueRotated(),
        rng=Crand(0),
        effects=EffectPool(),
        detail_preset=5,
        violence_disabled=0,
    )
    assert pool.entries[6].active is True

    spawned_idx = survival_spawn_creature(pool, Vec2(-40.0, 463.0), Crand(0), player_experience=0)
    assert spawned_idx == 22


def test_full_pool_spawns_write_the_phantom_slot_without_a_phase_seed() -> None:
    pool = CreaturePool()
    for entry in pool.entries:
        entry.active = True
        entry.hp = 1.0
    rng = RecordingCrand(Crand(0))

    idx = creature_spawn(pool, Vec2(12.0, 34.0), RGBA(), CreatureTypeId.SPIDER_SP1, rng, survival_elapsed_ms=0)

    assert idx == PHANTOM_CREATURE_INDEX
    assert pool.phantom.pos == Vec2(12.0, 34.0)
    assert pool.phantom.type_id is CreatureTypeId.SPIDER_SP1
    assert pool.phantom.phase_seed == 0
    assert [record.caller for record in rng.records] == [
        RngCallerStatic.CREATURE_SPAWN_HEADING,
        RngCallerStatic.CREATURE_SPAWN_REWARD,
    ]
    assert pool.spawned_count == 0


def test_ai7_link_timer_uses_rounded_frame_dt_ms_for_boundary_crossing() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags.AI7_LINK_TIMER
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.link_index = -33
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.move_speed = 0.0
    creature.size = 45.0

    # 0.0329999998s is captured as frame_dt_ms_i32=33 in native traces.
    dt = 0.032999999821186066
    stub_rand = _StubRand([0x11])
    state.rng = stub_rand
    step_creatures(world, dt)

    assert creature.ai_mode == 7
    assert creature.link_index == 517

    pool.finalize_post_render_lifecycle()
    assert pool.entries[6].active is False


def test_ai7_link_timer_still_ticks_for_evil_eyes_frozen_target() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player.evil_eyes_target_creature = 0
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags.AI7_LINK_TIMER
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.link_index = 1
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.move_speed = 0.0
    creature.size = 45.0

    stub_rand = _StubRand([0x2A])
    state.rng = stub_rand
    step_creatures(world, 1.0 / 60.0)

    # Native ticks AI7 link timers before Evil Eyes movement freeze.
    assert creature.link_index == -742
    assert stub_rand._idx == 1


def test_ai7_link_timer_still_ticks_when_live_self_damage_kills_creature() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 1.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags.AI7_LINK_TIMER | CreatureFlags.SELF_DAMAGE_TICK_STRONG
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.link_index = -10
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.move_speed = 0.0
    creature.size = 45.0

    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    step_creatures(world, 0.01)

    # Native runs AI7 timer update before live-branch kill handling.
    assert creature.link_index == 500
    assert creature.ai_mode == 7


@pytest.mark.parametrize(
    ("hp", "lifecycle_stage"),
    [(1.0, CREATURE_LIFECYCLE_ALIVE), (-1.0, 10.0), (10.0, 10.0)],
)
def test_dead_creature_still_reevaluates_target_player(hp: float, lifecycle_stage: float) -> None:
    world = make_world(player_count=2)
    state = world.state
    player0 = world.players[0]
    player0.pos = Vec2(500.0, 100.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    player1 = world.players[1]
    player1.pos = Vec2(110.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = hp
    creature.max_hp = max(1.0, hp)
    creature.lifecycle_stage = lifecycle_stage
    creature.flags = CreatureFlags.SELF_DAMAGE_TICK_STRONG if hp > 0.0 else CreatureFlags(0)
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.move_speed = 0.0
    creature.size = 45.0

    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    step_creatures(world, 0.1)

    assert creature.lifecycle_stage != CREATURE_LIFECYCLE_ALIVE
    assert creature.target_player == 1


def test_fading_corpse_redirects_from_dead_single_player() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(500.0, 100.0)
    player.health = 0.0
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = -1.0
    creature.lifecycle_stage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.size = 45.0

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 0.1)

    assert creature.target_player == 1


def test_dead_link_cleanup_finishes_current_live_interaction_tail() -> None:
    world = make_world()
    state = world.state
    state.bonus_spawn_guard = True
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.max_hp = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.ai_mode = CreatureAiMode.FOLLOW_LINK_TETHERED
    creature.link_index = 1
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.move_speed = 0.0
    creature.size = 44.0
    creature.contact_damage = 7.0

    dead_link = pool.entries[1]
    dead_link.active = False
    dead_link.hp = 0.0

    step_creatures(world, 0.1)

    assert creature.ai_mode == CreatureAiMode.ORBIT_PLAYER
    assert_float_close(player.health, 93.0)
    assert_float_close(creature.attack_cooldown, 1.0)
    assert creature.lifecycle_stage > CREATURE_LIFECYCLE_ALIVE - 1.0


def test_ai7_non_spawner_idle_keeps_previous_velocity() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags.AI7_LINK_TIMER
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.link_index = 400
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.vel = Vec2(2.0, -3.0)
    creature.move_speed = 4.2
    creature.size = 45.0

    state.rng = RecordingCrand(Crand(0x1234))
    step_creatures(world, 1.0 / 60.0)

    # Native `creature_update_all` skips movement work for AI7 here without
    # writing vel=0 for non-spawner creatures.
    assert creature.vel == Vec2(2.0, -3.0)
    assert creature.pos == Vec2(640.0, 512.0)


def test_evil_eyes_target_skips_cooldown_and_keeps_velocity() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player.evil_eyes_target_creature = 0
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags.AI7_LINK_TIMER
    creature.ai_mode = CreatureAiMode.HOLD_TIMER
    creature.link_index = 100
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.vel = Vec2(2.0, -3.0)
    creature.attack_cooldown = 1.0
    creature.move_speed = 0.0
    creature.size = 45.0

    stub_rand = _StubRand([0x2A])
    state.rng = stub_rand
    step_creatures(world, 1.0 / 60.0)

    # Native Evil Eyes path jumps to loop tail before cooldown/interaction/ranged branches.
    assert_float_close(creature.attack_cooldown, 1.0)
    assert creature.vel == Vec2(2.0, -3.0)
    assert creature.pos == Vec2(640.0, 512.0)
    assert creature.link_index == 84
    assert creature.force_target == 0
    assert stub_rand._idx == 0


def test_evil_eyes_target_still_takes_plague_infection_tick() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(512.0, 512.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player.evil_eyes_target_creature = 0
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.plague_infected = True
    creature.collision_timer = 0.1
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.move_speed = 1.0
    creature.size = 50.0

    before_pos = creature.pos
    step_creatures(world, 0.2)

    assert_float_close(creature.hp, 85.0)
    assert creature.collision_timer == f32(0.4)
    assert creature.pos == before_pos


def test_evil_eyes_target_still_reevaluates_target_player() -> None:
    world = make_world(player_count=2)
    state = world.state
    player0 = world.players[0]
    player0.pos = Vec2(500.0, 100.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player0.evil_eyes_target_creature = 0
    player1 = world.players[1]
    player1.pos = Vec2(110.0, 100.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    pool = world.creatures

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.move_speed = 1.0
    creature.size = 50.0

    before_pos = creature.pos
    step_creatures(world, 0.2)

    assert creature.target_player == 1
    assert creature.pos == before_pos


def test_evil_eyes_default_freezes_targets_from_multiple_players() -> None:
    world = make_world(player_count=2)
    state = world.state

    player0 = world.players[0]
    player0.pos = Vec2(512.0, 512.0)
    player0.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player0.evil_eyes_target_creature = 0

    player1 = world.players[1]
    player1.pos = Vec2(520.0, 512.0)
    player1.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL)
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player1.evil_eyes_target_creature = 1

    pool = world.creatures

    creature0 = pool.entries[0]
    creature0.active = True
    creature0.hp = 50.0
    creature0.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature0.flags = CreatureFlags.AI7_LINK_TIMER
    creature0.ai_mode = CreatureAiMode.HOLD_TIMER
    creature0.link_index = 100
    creature0.target_player = 0
    creature0.pos = Vec2(640.0, 512.0)
    creature0.vel = Vec2(2.0, -3.0)
    creature0.attack_cooldown = 1.0
    creature0.move_speed = 0.0
    creature0.size = 45.0

    creature1 = pool.entries[1]
    creature1.active = True
    creature1.hp = 50.0
    creature1.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature1.flags = CreatureFlags.AI7_LINK_TIMER
    creature1.ai_mode = CreatureAiMode.HOLD_TIMER
    creature1.link_index = 100
    creature1.target_player = 0
    creature1.pos = Vec2(680.0, 512.0)
    creature1.vel = Vec2(2.0, -3.0)
    creature1.attack_cooldown = 1.0
    creature1.move_speed = 0.0
    creature1.size = 45.0

    stub_rand = _StubRand([0x2A, 0x2B])
    state.rng = stub_rand
    step_creatures(world, 1.0 / 60.0)

    assert_float_close(creature0.attack_cooldown, 1.0)
    assert_float_close(creature1.attack_cooldown, 1.0)
    assert creature0.vel == Vec2(2.0, -3.0)
    assert creature1.vel == Vec2(2.0, -3.0)
    assert creature0.force_target == 0
    assert creature1.force_target == 0


def test_bonus_on_death_drop_emits_native_burst_and_clamps_corpse() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True
    draw_callers: list[int | None] = []
    rng = Crand(1)
    rng.set_trace_sink(
        lambda _before, _after, _value, caller: draw_callers.append(caller),
        require_caller=True,
    )
    state.rng = rng
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.BONUS_ON_DEATH
    creature.bonus_id = BonusId.POINTS
    creature.bonus_duration_override = 5
    creature.pos = Vec2(5.0, 1010.0)
    creature.hp = 0.0

    pool.handle_death(
        0,
        state=state,
        players=[PlayerState(index=0, pos=Vec2())],
        rng=state.rng,
        fx_queue=None,
    )

    # Native bonus_spawn_at clamps the corpse position through the pointer and
    # always spawns a 16-particle burst (4 crt_rand draws each).
    assert creature.pos == Vec2(32.0, 992.0)
    assert len(state.effects.iter_active()) == 16
    entry = next(e for e in state.bonus_pool.entries if e.bonus_id == BonusId.POINTS)
    assert entry.pos == Vec2(32.0, 992.0)
    assert len(draw_callers) == 64
    assert draw_callers[:4] == [
        RngCallerStatic.BONUS_SPAWN_AT_BURST_ROTATION,
        RngCallerStatic.BONUS_SPAWN_AT_BURST_VEL_X,
        RngCallerStatic.BONUS_SPAWN_AT_BURST_VEL_Y,
        RngCallerStatic.BONUS_SPAWN_AT_BURST_SCALE_STEP,
    ]


def test_long_strip_spawner_clamps_only_before_moving() -> None:
    # creature_update_all clamps PING_PONG movers to [size, 1024 - size] before
    # the move; the step itself may carry a long-strip mover past the bound.
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(1500.0, 500.0)
    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.size = 64.0
    creature.move_speed = 2.0
    creature.pos = Vec2(975.0, 500.0)
    creature.heading = f32(math.pi / 2.0)
    creature.target_heading = creature.heading
    creature.flags = CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP

    state.rng = Crand(0)
    step_creatures(world, 1.0 / 60.0)

    assert creature.vel.x > 0.0
    assert creature.pos.x == x87_pc24_add(960.0, creature.vel.x)
