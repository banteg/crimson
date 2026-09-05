from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest

import crimson.creatures.runtime as creature_runtime
from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusEntry
from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import (
    HAS_SPAWN_SLOT_FLAG,
    NATIVE_SPAWN_SLOT_COUNT,
    RANDOM_HEADING_SENTINEL,
    CreatureAiMode,
    CreatureFlags,
    CreatureInit,
    CreatureTypeId,
    SpawnEnv,
    SpawnId,
    SpawnSlotInit,
    build_spawn_plan,
)
from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import prepare_weapon_availability
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand
from grim.sfx_map import SfxId
from tests.support.factories import make_creature_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression


def test_spawn_plan_remaps_ai_links_with_pool_offset() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    plan = build_spawn_plan(SpawnId.FORMATION_CHAIN_ALIEN_10_13, Vec2(100.0, 200.0), 0.0, rng, env)

    pool = CreaturePool()
    # Occupy a few pool slots so plan-local indices do not equal pool indices.
    for i in range(5):
        pool.entries[i].active = True
        pool.entries[i].hp = 1.0

    mapping, primary = pool.spawn_plan(plan)
    assert primary == mapping[plan.primary]

    # Assert that link indices were remapped from plan-local indices -> pool indices.
    for plan_idx, pool_idx in enumerate(mapping):
        init = plan.creatures[plan_idx]
        if init.ai_link_parent is None:
            continue
        assert pool.entries[pool_idx].link_index == mapping[int(init.ai_link_parent)]


def test_spawn_plan_remaps_spawn_slot_indices() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    plan = build_spawn_plan(SpawnId.ZOMBIE_BOSS_SPAWNER_00, Vec2(100.0, 200.0), 0.0, rng, env)

    pool = CreaturePool()
    # Seed an existing spawn slot so the plan slot id (0) must be remapped.
    pool.entries[0].active = True
    pool.entries[0].hp = 1.0
    pool.spawn_slots.append(
        SpawnSlotInit(
            owner_creature=0,
            timer=0.0,
            count=0,
            limit=0,
            interval=1.0,
            child_template_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
        ),
    )

    mapping, primary = pool.spawn_plan(plan)
    assert primary == mapping[plan.primary]
    assert len(mapping) == 1
    assert len(pool.spawn_slots) == 2

    owner_idx = mapping[0]
    new_slot_idx = 1
    assert pool.entries[owner_idx].spawn_slot_index == new_slot_idx
    assert pool.entries[owner_idx].link_index == new_slot_idx
    assert pool.spawn_slots[new_slot_idx].owner_creature == owner_idx


def test_spawn_plan_reuses_native_spawn_slot_pool_and_overwrites_last_on_exhaustion() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    plan = build_spawn_plan(SpawnId.ZOMBIE_BOSS_SPAWNER_00, Vec2(100.0, 200.0), 0.0, rng, env)
    pool = CreaturePool()
    empty_slot = SpawnSlotInit(
        owner_creature=-1,
        timer=9.0,
        count=9,
        limit=9,
        interval=9.0,
        child_template_id=SpawnId.ALIEN_RANDOM_1D,
    )
    pool.spawn_slots.append(empty_slot)

    mapping, _ = pool.spawn_plan(plan)

    assert len(pool.spawn_slots) == 1
    assert pool.entries[mapping[0]].spawn_slot_index == 0
    assert pool.spawn_slots[0].owner_creature == mapping[0]

    pool = CreaturePool()
    for owner_index in range(NATIVE_SPAWN_SLOT_COUNT):
        pool.spawn_slots.append(
            SpawnSlotInit(
                owner_creature=owner_index,
                timer=0.0,
                count=0,
                limit=1,
                interval=1.0,
                child_template_id=SpawnId.ALIEN_RANDOM_1D,
            ),
        )

    mapping, _ = pool.spawn_plan(plan)

    assert len(pool.spawn_slots) == NATIVE_SPAWN_SLOT_COUNT
    assert pool.entries[mapping[0]].spawn_slot_index == NATIVE_SPAWN_SLOT_COUNT - 1
    assert pool.spawn_slots[-1].owner_creature == mapping[0]


def test_spawn_plan_materialization_spawns_burst_fx() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    state = GameplayState(rng=rng)
    pool = CreaturePool(env=env, effects=state.effects)

    plan = build_spawn_plan(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(100.0, 200.0), 0.0, rng, env)
    pool.spawn_plan(
        plan,
        rng=rng,
        detail_preset=5,
    )

    active = state.effects.iter_active()
    assert len(active) == 8
    assert all(int(entry.effect_id) == 0 for entry in active)


def test_hardcore_runtime_spawn_clears_shared_quest_retry_count() -> None:
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=True,
        quest_fail_retry_count=4,
    )
    pool = CreaturePool(env=env)

    pool.spawn_template(
        SpawnId.ALIEN_HIDDEN_1_21,
        Vec2(100.0, 200.0),
        0.0,
        Crand(0xBEEF),
    )

    assert env.quest_fail_retry_count == 0
    assert pool.env is env


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
    state = GameplayState()
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    pool = CreaturePool(env=env)

    owner = pool.entries[0]
    owner.active = True
    owner.hp = 100.0
    owner.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    owner.flags = HAS_SPAWN_SLOT_FLAG
    owner.heading = 1.234
    owner.pos = Vec2(200.0, 300.0)
    owner.spawn_slot_index = 0
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))

    pool.spawn_slots.append(
        SpawnSlotInit(
            owner_creature=0,
            timer=0.0,
            count=0,
            limit=1,
            interval=1.0,
            child_template_id=SpawnId.ALIEN_RANDOM_1D,
        ),
    )

    sentinel_plan = object()

    def _fake_spawn_plan(self: CreaturePool, plan: object, **kwargs: object) -> tuple[list[int], int | None]:
        del self, plan, kwargs
        return [], None

    build_spawn_plan = mocker.patch.object(creature_runtime, "build_spawn_plan", return_value=sentinel_plan)
    spawn_plan = mocker.patch.object(CreaturePool, "spawn_plan", autospec=True, side_effect=_fake_spawn_plan)

    pool.update(1.0 / 60.0, options=make_creature_update_options(state=state, players=[player], env=env))

    build_spawn_plan.assert_called_once()
    child_template_id = int(build_spawn_plan.call_args.args[0])
    heading = float(build_spawn_plan.call_args.args[2])
    env_arg = cast("SpawnEnv", build_spawn_plan.call_args.args[4])
    assert child_template_id == int(SpawnId.ALIEN_RANDOM_1D)
    assert_float_close(heading, RANDOM_HEADING_SENTINEL)
    assert env_arg is env
    spawn_plan.assert_called_once()


def test_spawn_slot_update_requires_spawner_flag() -> None:
    state = GameplayState()
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    pool = CreaturePool(env=env)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))

    owner = pool.entries[0]
    owner.active = True
    owner.hp = 100.0
    owner.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    owner.flags = CreatureFlags(0)
    owner.ai_mode = CreatureAiMode.ORBIT_PLAYER
    owner.move_speed = 0.0
    owner.size = 45.0
    owner.pos = Vec2(256.0, 256.0)
    owner.spawn_slot_index = 0

    pool.spawn_slots.append(
        SpawnSlotInit(
            owner_creature=0,
            timer=0.0,
            count=0,
            limit=1,
            interval=1.0,
            child_template_id=SpawnId.ALIEN_RANDOM_1D,
        ),
    )

    pool.update(1.0 / 60.0, options=make_creature_update_options(state=state, players=[player], env=env))

    assert pool.spawn_slots[0].count == 0
    assert_float_close(pool.spawn_slots[0].timer, 0.0)
    assert [idx for idx, creature in enumerate(pool.entries) if idx != 0 and creature.active] == []


def test_spawn_slot_child_can_update_in_same_tick() -> None:
    state = GameplayState()
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    pool = CreaturePool(env=env)
    player = PlayerState(index=0, pos=Vec2(640.0, 700.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))

    owner = pool.entries[0]
    owner.active = True
    owner.hp = 100.0
    owner.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    owner.pos = Vec2(256.0, 256.0)
    owner.flags = HAS_SPAWN_SLOT_FLAG
    owner.ai_mode = CreatureAiMode.ORBIT_PLAYER
    owner.move_speed = 0.0
    owner.size = 45.0
    owner.spawn_slot_index = 0

    pool.spawn_slots.append(
        SpawnSlotInit(
            owner_creature=0,
            timer=0.0,
            count=0,
            limit=1,
            interval=1.0,
            child_template_id=SpawnId.ALIEN_BIG_GRAY_29,
        ),
    )

    pool.update(1.0 / 60.0, options=make_creature_update_options(state=state, players=[player], env=env))

    child_indices = [idx for idx, creature in enumerate(pool.entries) if idx != 0 and creature.active]
    assert child_indices
    child = pool.entries[child_indices[0]]
    assert child.target_heading is not None
    assert abs(float(child.target_heading)) > 1e-6
    assert child.pos != Vec2(256.0, 256.0)


def test_non_spawner_update_does_not_clamp_offscreen_positions() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.flags = CreatureFlags(0)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(-64.0, 1088.0)

    pool.update(1.0 / 60.0, options=make_creature_update_options(state=state, players=[player]))

    assert_float_close(creature.pos.x, -64.0)
    assert_float_close(creature.pos.y, 1088.0)


def test_attack_cooldown_is_stored_at_native_precision() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(128.0, 128.0)
    creature.attack_cooldown = 1.0

    options = make_creature_update_options(state=state, players=[player])
    pool.update(0.1, options=options)
    pool.update(0.1, options=options)

    expected = f32(f32(1.0 - f32(0.1)) - f32(0.1))
    assert creature.attack_cooldown == expected


def test_non_spawner_movement_is_independent_of_creature_type_id() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    base = pool.entries[0]
    variant = pool.entries[1]
    base_delta = base.pos - start_pos
    variant_delta = variant.pos - start_pos

    assert_float_close(variant_delta.x, base_delta.x)
    assert_float_close(variant_delta.y, base_delta.y)
    assert_float_close(variant.vel.x, base.vel.x)
    assert_float_close(variant.vel.y, base.vel.y)


def test_ai_mode5_near_link_scales_runtime_movement_delta() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(900.0, 900.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

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
    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    near_step = (near.pos - near_start).length()
    far_step = (far.pos - far_start).length()

    assert_float_close(near.move_scale, 50.0 * 0.015625)
    assert_float_close(far.move_scale, 1.0)
    assert near_step < far_step
    assert_float_close(far_step, 0.9999993146409377)
    assert_float_close(near_step, 0.7812510393925548)


def test_creature_contact_damage_targets_player1_when_player0_is_dead() -> None:
    state = GameplayState()
    pool = CreaturePool()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    player0 = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=0.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )
    player1 = PlayerState(
        index=1,
        pos=Vec2(110.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=rng,
        ),
    )

    assert creature.target_player == 1
    assert_float_close(player0.health, 0.0)
    assert_float_close(player1.health, 90.0)
    assert [record.caller for record in rng.records_since() if record.caller is not None][:1] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_CONTACT_SFX,
    ]


def test_near_player_movement_rollback_is_stored_at_native_precision() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 1.3
    creature.size = 45.0
    creature.pos = Vec2(110.0, 100.0)
    creature.target_player = 0

    pool.update(0.1, options=make_creature_update_options(state=state, players=[player]))

    assert creature.pos.x == f32(creature.pos.x)
    assert creature.pos.y == f32(creature.pos.y)


def test_contact_cooldown_addition_is_stored_at_native_precision() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(100.0, 100.0)
    creature.attack_cooldown = f32(0.077)

    dt = f32(0.084)
    pool.update(dt, options=make_creature_update_options(state=state, players=[player]))

    expected = x87_pc24_add(x87_pc24_sub(f32(0.077), dt), f32(1.0))
    assert creature.attack_cooldown == expected


def test_creature_eat_gate_uses_stored_native_distance() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(0.01, options=make_creature_update_options(state=state, players=[player]))

    assert creature.pos == Vec2(19.999998092651367, 0.003907000180333853)


def test_creature_contact_gate_uses_stored_native_distance() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    result = pool.update(0.01, options=make_creature_update_options(state=state, players=[player]))

    assert player.health == 100.0
    assert creature.attack_cooldown == 0.0
    assert result.sfx == ()


def test_plague_kill_uses_exact_native_attack_sfx_caller() -> None:
    state = GameplayState()
    pool = CreaturePool()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))

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

    result = pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=rng,
        ),
    )

    assert result.sfx == (SfxId.ZOMBIE_ATTACK_01,)
    assert [record.caller for record in rng.records_since() if record.caller is not None] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_PLAGUE_KILL_SFX,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
    ]


def test_plague_infection_timer_keeps_native_stored_cadence() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0))
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
        pool.update(0.02, options=make_creature_update_options(state=state, players=[player]))

    assert creature.hp == 70.0
    assert creature.collision_timer == 0.49999991059303284


def test_radioactive_timer_keeps_native_stored_cadence() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1
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
        pool.update(1.0 / 120.0, options=make_creature_update_options(state=state, players=[player]))

    assert creature.hp == 97.0
    assert creature.collision_timer == 1.8440186977386475e-07


def test_single_player_dead_player_uses_dead_target_position() -> None:
    state = GameplayState()
    pool = CreaturePool()

    dead_player = PlayerState(
        index=0,
        pos=Vec2(660.0, 520.0),
        health=0.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[dead_player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    expected_dead_target = Vec2(1024.0 * (27.0 / 64.0), 1024.0 * (27.0 / 64.0))
    assert creature.target_player == 1
    assert creature.target == Vec2(569.058349609375, expected_dead_target.y)

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[dead_player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert creature.target == Vec2(513.7415771484375, expected_dead_target.y)


def test_single_player_dead_player_contact_path_keeps_dead_player_undamaged() -> None:
    state = GameplayState()
    pool = CreaturePool()

    dead_player = PlayerState(
        index=0,
        pos=Vec2(400.0, 400.0),
        health=0.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[dead_player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    expected_dead_target = Vec2(1024.0 * (27.0 / 64.0), 1024.0 * (27.0 / 64.0))
    assert creature.target_player == 1
    assert creature.target == expected_dead_target
    assert creature.attack_cooldown == 1.0
    assert_float_close(dead_player.health, 0.0)


def test_creature_retargets_to_closer_player1_in_two_player_mode() -> None:
    state = GameplayState()
    pool = CreaturePool()

    player0 = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )
    player1 = PlayerState(
        index=1,
        pos=Vec2(104.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

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
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert player.auto_target == 1


def test_creature_update_auto_target_falls_back_when_previous_target_is_dead() -> None:
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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
    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

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
    state = GameplayState()
    pool = CreaturePool()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )
    assert pool._update_tick == creature_runtime._TARGET_REEVAL_PERIOD
    assert player.auto_target == 0

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )
    assert player.auto_target == 1


def test_creature_update_coop_auto_target_uses_target_player_position_by_default() -> None:
    state = GameplayState(preserve_bugs=False)
    pool = CreaturePool()
    player0 = PlayerState(
        index=0,
        pos=Vec2(0.0, 0.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )
    player1 = PlayerState(
        index=1,
        pos=Vec2(100.0, 0.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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
    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert player1.auto_target == 1


def test_creature_update_coop_auto_target_preserve_bugs_keeps_player1_distance_bias() -> None:
    state = GameplayState(preserve_bugs=True)
    pool = CreaturePool()
    player0 = PlayerState(
        index=0,
        pos=Vec2(0.0, 0.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )
    player1 = PlayerState(
        index=1,
        pos=Vec2(100.0, 0.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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
    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert player1.auto_target == 0


def test_creature_update_coop_auto_target_preserve_bugs_reuses_other_player_distance() -> None:
    state = GameplayState(preserve_bugs=True)
    pool = CreaturePool()
    player0 = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=100.0, auto_target=0)
    player1 = PlayerState(index=1, pos=Vec2(100.0, 0.0), health=100.0)

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    # The candidate is 10 units from player 1, but native reuses its 90-unit
    # distance from player 2. It therefore does not replace the 50-unit slot.
    assert player0.auto_target == 0


def test_creature_update_preserve_bugs_updates_dead_auto_target_before_redirect() -> None:
    state = GameplayState(preserve_bugs=True)
    pool = CreaturePool()
    player0 = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=0.0, auto_target=0)
    player1 = PlayerState(index=1, pos=Vec2(100.0, 0.0), health=100.0, auto_target=0)

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert player0.auto_target == 1
    assert player1.auto_target == 0
    assert candidate.target_player == 1


def test_small_creature_dies_on_contact() -> None:
    state = GameplayState()
    pool = CreaturePool()

    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=100.0,
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE),
    )

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
    pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

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
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )
    assert death.xp_awarded == 10
    assert player.experience == 10
    assert any(entry.bonus_id != BonusId.UNUSED for entry in state.bonus_pool.entries)
    assert len(state.effects.iter_active()) == 16
    # Successful spawn-on-kill emits a 16-particle burst (4 RNG draws each).
    assert stub_rand._idx == 67


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_experience"),
    [
        (True, (13, 0)),
        (False, (0, 10)),
    ],
    ids=["native-player-zero", "corrected-last-hit-owner"],
)
def test_death_award_player_source_policy(
    preserve_bugs: bool,
    expected_experience: tuple[int, int],
) -> None:
    state = GameplayState(preserve_bugs=preserve_bugs)
    state.bonus_spawn_guard = True
    players = [
        PlayerState(index=0, pos=Vec2()),
        PlayerState(index=1, pos=Vec2()),
    ]
    players[0].perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1
    pool = CreaturePool()
    pool.entries[0].active = True
    pool.entries[0].hp = 0.0
    pool.entries[0].reward_value = 10.0
    pool.entries[0].last_hit_owner = OwnerRef.from_local_player(1)

    death = pool.handle_death(
        0,
        state=state,
        players=players,
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )

    assert death.xp_awarded == max(expected_experience)
    assert (players[0].experience, players[1].experience) == expected_experience


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
        world_width=1024.0,
        world_height=1024.0,
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
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )

    spawn_at.assert_called_once()
    try_spawn_on_kill.assert_called_once()
    assert state.effects.iter_active() == []


def test_handle_death_shock_flag_has_no_resolved_death_sfx_without_spawning_debris() -> None:
    state = GameplayState()
    stub_rand = _StubRand([0] * 20)
    state.rng = stub_rand
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 0.0

    pool.handle_death(
        0,
        state=state,
        players=[],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
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
        world_width=1024.0,
        world_height=1024.0,
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
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=fx_queue,
    )

    add_random.assert_not_called()


def test_handle_death_freeze_enqueues_fx_queue_random_once(mocker) -> None:
    state = GameplayState()
    state.game_mode = GameMode.RUSH
    state.bonuses.freeze = 1.0
    state.rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
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
        world_width=1024.0,
        world_height=1024.0,
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
        world_width=1024.0,
        world_height=1024.0,
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
        players=[],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )
    pool.handle_death(
        0,
        state=state,
        players=[],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
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
        players=[],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )
    pool.handle_death(
        0,
        state=state,
        players=[],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )

    assert spawn_at.call_count == 2


def test_spawn_inits_resets_native_spawn_state_fields() -> None:
    pool = CreaturePool()
    (idx,) = pool.spawn_inits(
        [
            CreatureInit(
                origin_template_id=0x99,
                pos=Vec2(100.0, 200.0),
                heading=0.75,
                phase_seed=10,
                type_id=CreatureTypeId.ALIEN,
                health=40.0,
                max_health=40.0,
                move_speed=2.0,
                reward_value=12.0,
                size=45.0,
                contact_damage=6.0,
            ),
        ],
    )
    entry = pool.entries[idx]

    assert entry.active is True
    assert entry.vel == Vec2()
    assert entry.force_target == 0
    assert_float_close(entry.attack_cooldown, 0.0)
    assert_float_close(entry.collision_timer, 0.0)
    assert_float_close(entry.hit_flash_timer, 0.0)
    assert_float_close(entry.anim_phase, 0.0)
    assert entry.last_hit_owner == OwnerRef.from_local_player(0)


def test_spawn_init_preserves_stale_link_index_for_implicit_ai7_timer() -> None:
    pool = CreaturePool()
    pool.entries[0].link_index = -1

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x75,
            pos=Vec2(1064.0, 392.0),
            heading=0.0,
            phase_seed=0,
            type_id=CreatureTypeId.SPIDER_SP1,
            flags=CreatureFlags.AI7_LINK_TIMER,
            ai_mode=0,
            health=54.0,
            max_health=54.0,
            move_speed=1.17,
            reward_value=0.0,
            size=56.0,
            contact_damage=5.0,
        ),
    )

    assert idx is not None
    assert idx == 0
    assert pool.entries[idx].link_index == -1


def test_spawn_init_preserves_stale_force_target_from_recycled_slot() -> None:
    pool = CreaturePool()
    pool.entries[0].force_target = 1

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x12,
            pos=Vec2(100.0, 200.0),
            heading=0.0,
            phase_seed=0,
            preserve_force_target=True,
            type_id=CreatureTypeId.ALIEN,
            health=40.0,
            max_health=40.0,
        ),
    )

    assert idx == 0
    assert pool.entries[idx].force_target == 1


def test_spawn_template_preserves_stale_ranged_orbit_fields() -> None:
    pool = CreaturePool()
    pool.entries[0].orbit_angle = 0.4
    pool.entries[0].orbit_radius = float(ProjectileTemplateId.SPIDER_PLASMA)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    mapping, primary = pool.spawn_template(
        SpawnId.SPIDER_SP2_RANGED_VARIANT_37,
        Vec2(100.0, 200.0),
        0.0,
        Crand(0xBEEF),
        env=env,
    )

    assert mapping == [0]
    assert primary == 0
    assert_float_close(pool.entries[0].orbit_angle, 0.4)
    assert pool.entries[0].orbit_radius == float(ProjectileTemplateId.SPIDER_PLASMA)


def test_spawn_init_preserves_stale_target_heading_from_recycled_slot() -> None:
    pool = CreaturePool()
    pool.entries[0].target_heading = 2.5632283687591553

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x75,
            pos=Vec2(-40.0, 812.0),
            heading=0.53,
            phase_seed=323,
            type_id=CreatureTypeId.SPIDER_SP1,
            flags=CreatureFlags.AI7_LINK_TIMER,
            ai_mode=0,
            health=63.86125183105469,
            max_health=63.86125183105469,
            move_speed=1.3,
            reward_value=43.0,
            size=44.0,
            contact_damage=4.0,
        ),
    )

    assert idx is not None
    assert idx == 0
    assert_float_close(pool.entries[idx].heading, float(f32(0.53)))
    assert_float_close(pool.entries[idx].target_heading, 2.5632283687591553)


def test_spawn_init_preserves_stale_target_from_recycled_slot() -> None:
    pool = CreaturePool()
    pool.entries[0].target = Vec2(7.0, 8.0)

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x75,
            pos=Vec2(-40.0, 272.0),
            heading=3.07,
            phase_seed=0,
            type_id=CreatureTypeId.SPIDER_SP1,
            flags=CreatureFlags.AI7_LINK_TIMER,
            ai_mode=0,
            health=61.0,
            max_health=61.0,
            move_speed=1.17,
            reward_value=0.0,
            size=56.0,
            contact_damage=5.0,
        ),
    )

    assert idx == 0
    assert pool.entries[idx].target == Vec2(7.0, 8.0)


def test_spawn_init_preserves_stale_target_offset_from_recycled_slot() -> None:
    pool = CreaturePool()
    pool.entries[0].target_offset = Vec2(-70.71066284179688, -70.710693359375)

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=-1,
            pos=Vec2(100.0, 200.0),
            heading=0.0,
            phase_seed=0,
            type_id=CreatureTypeId.ALIEN,
            health=40.0,
            max_health=40.0,
        ),
    )

    assert idx == 0
    assert pool.entries[idx].target_offset == Vec2(-70.71066284179688, -70.710693359375)


def test_spawn_init_ai_timer_still_overrides_link_index() -> None:
    pool = CreaturePool()
    pool.entries[0].link_index = -1

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x38,
            pos=Vec2(1064.0, 392.0),
            heading=0.0,
            phase_seed=0,
            type_id=CreatureTypeId.SPIDER_SP1,
            flags=CreatureFlags.AI7_LINK_TIMER,
            ai_mode=0,
            ai_timer=0,
            health=50.0,
            max_health=50.0,
            move_speed=4.8,
            reward_value=433.0,
            size=43.0,
            contact_damage=10.0,
        ),
    )

    assert idx is not None
    assert idx == 0
    assert pool.entries[idx].link_index == 0


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
        world_width=1024.0,
        world_height=1024.0,
        fx_queue_rotated=None,
    )

    assert corpse.active is True
    assert_float_close(corpse.lifecycle_stage, f32(-10.016))

    pool.finalize_post_render_lifecycle()
    assert corpse.active is False


def test_tick_dead_ping_pong_corpse_emits_native_19_blood_burst_rng_budget() -> None:
    state = GameplayState()
    pool = CreaturePool(effects=state.effects)
    corpse = pool.entries[0]
    corpse.active = True
    corpse.hp = -5.0
    corpse.lifecycle_stage = 1.0
    corpse.pos = Vec2(320.0, 240.0)
    corpse.flags = CreatureFlags.ANIM_PING_PONG
    corpse.size = 24.0

    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    pool._tick_dead(
        corpse,
        dt=0.1,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue_rotated=None,
        rng=rng,
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
    assert len(state.effects.iter_active()) == 38


def test_dead_self_damage_tick_flags_still_reduce_lifecycle_before_dead_decay() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

    corpse = pool.entries[42]
    corpse.active = True
    corpse.hp = -0.08500146865844727
    corpse.lifecycle_stage = 12.640003204345703
    corpse.flags = CreatureFlags.SELF_DAMAGE_TICK

    # Exercise a non-round frame time at the native damage boundary.
    pool.update(
        0.03800000250339508,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    # Native applies SELF_DAMAGE_TICK via creature_apply_damage even while hp<=0.
    assert_float_close(corpse.lifecycle_stage, f32(11.006003))


def test_newly_dead_self_damage_tick_preserves_native_prologue_order() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

    corpse = pool.entries[42]
    corpse.active = True
    corpse.hp = -1.0
    corpse.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    corpse.flags = CreatureFlags.SELF_DAMAGE_TICK

    dt = f32(0.03800000250339508)
    pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    expected = x87_pc24_sub(
        x87_pc24_sub(
            x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, dt),
            x87_pc24_mul(dt, 15.0),
        ),
        x87_pc24_mul(dt, 28.0),
    )
    assert corpse.lifecycle_stage == expected


def test_live_self_damage_product_is_stored_at_native_precision() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

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
    pool.update(dt, options=make_creature_update_options(state=state, players=[player]))

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
        world_width=1024.0,
        world_height=1024.0,
        fx_queue_rotated=None,
    )

    assert corpse.lifecycle_stage == 14.256000518798828
    assert corpse.vel == Vec2(0.3601662218570709, -7.56136417388916)


def test_spawn_allocation_uses_slot_still_active_until_post_render_cleanup() -> None:
    pool = CreaturePool(size=24)
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
        world_width=1024.0,
        world_height=1024.0,
        fx_queue_rotated=None,
    )
    assert pool.entries[6].active is True

    spawned_idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=-1,
            pos=Vec2(-40.0, 463.0),
            heading=0.0,
            phase_seed=17,
            type_id=CreatureTypeId.LIZARD,
            health=60.6925,
            max_health=60.6925,
            move_speed=1.0,
            reward_value=0.0,
            size=50.0,
            contact_damage=4.0,
        ),
    )
    assert spawned_idx is not None
    assert spawned_idx == 22


def test_spawn_init_returns_none_when_pool_is_full() -> None:
    pool = CreaturePool(size=1)
    pool.entries[0].active = True
    pool.entries[0].hp = 1.0

    spawned_idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0,
            pos=Vec2(12.0, 34.0),
            heading=0.0,
            phase_seed=0,
            type_id=CreatureTypeId.ZOMBIE,
            health=10.0,
            max_health=10.0,
            move_speed=1.0,
            reward_value=1.0,
            size=10.0,
            contact_damage=1.0,
        ),
    )

    assert spawned_idx is None
    assert pool.entries[0].active is True
    assert pool.spawned_count == 0


def test_spawn_plan_returns_empty_when_pool_cannot_fit_plan() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    pool = CreaturePool(size=1, env=env)
    pool.entries[0].active = True
    pool.entries[0].hp = 1.0

    plan = build_spawn_plan(SpawnId.ALIEN_RANDOM_1D, Vec2(100.0, 200.0), 0.0, rng, env)

    mapping, primary = pool.spawn_plan(plan)

    assert mapping == []
    assert primary is None
    assert pool.spawned_count == 0


def test_ai7_link_timer_uses_rounded_frame_dt_ms_for_boundary_crossing() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

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
    pool.update(dt, options=make_creature_update_options(state=state, players=[player], rng=stub_rand))

    assert creature.ai_mode == 7
    assert creature.link_index == 517

    pool.finalize_post_render_lifecycle()
    assert pool.entries[6].active is False


def test_ai7_link_timer_still_ticks_for_evil_eyes_frozen_target() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player.evil_eyes_target_creature = 0
    pool = CreaturePool()

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
    pool.update(1.0 / 60.0, options=make_creature_update_options(state=state, players=[player], rng=stub_rand))

    # Native ticks AI7 link timers before Evil Eyes movement freeze.
    assert creature.link_index == -742
    assert stub_rand._idx == 1


def test_ai7_link_timer_still_ticks_when_live_self_damage_kills_creature() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    prepare_weapon_availability(state)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

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

    pool.update(
        0.01,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    # Native runs AI7 timer update before live-branch kill handling.
    assert creature.link_index == 500
    assert creature.ai_mode == 7


@pytest.mark.parametrize(
    ("hp", "lifecycle_stage"),
    [(1.0, CREATURE_LIFECYCLE_ALIVE), (-1.0, 10.0), (10.0, 10.0)],
)
def test_dead_creature_still_reevaluates_target_player(hp: float, lifecycle_stage: float) -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    prepare_weapon_availability(state)
    player0 = PlayerState(index=0, pos=Vec2(500.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player1 = PlayerState(index=1, pos=Vec2(110.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

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

    pool.update(
        0.1,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert creature.lifecycle_stage != CREATURE_LIFECYCLE_ALIVE
    assert creature.target_player == 1


def test_fading_corpse_redirects_from_dead_single_player() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(500.0, 100.0), health=0.0)
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.hp = -1.0
    creature.lifecycle_stage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(100.0, 100.0)
    creature.size = 45.0

    pool.update(
        0.1,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert creature.target_player == 1


def test_dead_link_cleanup_finishes_current_live_interaction_tail() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=100.0)
    pool = CreaturePool()

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

    pool.update(0.1, options=make_creature_update_options(state=state, players=[player]))

    assert creature.ai_mode == CreatureAiMode.ORBIT_PLAYER
    assert_float_close(player.health, 93.0)
    assert_float_close(creature.attack_cooldown, 1.0)
    assert creature.lifecycle_stage > CREATURE_LIFECYCLE_ALIVE - 1.0


def test_ai7_non_spawner_idle_keeps_previous_velocity() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

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

    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    # Native `creature_update_all` skips movement work for AI7 here without
    # writing vel=0 for non-spawner creatures.
    assert creature.vel == Vec2(2.0, -3.0)
    assert creature.pos == Vec2(640.0, 512.0)


def test_evil_eyes_target_skips_cooldown_and_keeps_velocity() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player.evil_eyes_target_creature = 0
    pool = CreaturePool()

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
    pool.update(1.0 / 60.0, options=make_creature_update_options(state=state, players=[player], rng=stub_rand))

    # Native Evil Eyes path jumps to loop tail before cooldown/interaction/ranged branches.
    assert_float_close(creature.attack_cooldown, 1.0)
    assert creature.vel == Vec2(2.0, -3.0)
    assert creature.pos == Vec2(640.0, 512.0)
    assert creature.link_index == 84
    assert creature.force_target == 0
    assert stub_rand._idx == 0


def test_evil_eyes_target_still_takes_plague_infection_tick() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player.evil_eyes_target_creature = 0
    pool = CreaturePool()

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
    pool.update(0.2, options=make_creature_update_options(state=state, players=[player]))

    assert_float_close(creature.hp, 85.0)
    assert creature.collision_timer == f32(0.4)
    assert creature.pos == before_pos


def test_evil_eyes_target_still_reevaluates_target_player() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player0 = PlayerState(index=0, pos=Vec2(500.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player0.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player0.evil_eyes_target_creature = 0
    player1 = PlayerState(index=1, pos=Vec2(110.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    pool = CreaturePool()

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
    pool.update(0.2, options=make_creature_update_options(state=state, players=[player0, player1]))

    assert creature.target_player == 1
    assert creature.pos == before_pos


def test_evil_eyes_default_freezes_targets_from_multiple_players() -> None:
    state = GameplayState(rng=Crand(0xBEEF), preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player0.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player0.evil_eyes_target_creature = 0

    player1 = PlayerState(index=1, pos=Vec2(520.0, 512.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    player1.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player1.evil_eyes_target_creature = 1

    pool = CreaturePool()

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
    pool.update(
        1.0 / 60.0,
        options=make_creature_update_options(state=state, players=[player0, player1], rng=stub_rand),
    )

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
        players=[],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
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
