from __future__ import annotations

from grim.geom import Vec2

from dataclasses import dataclass

import pytest

from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PlayerState
from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags, CreatureInit, CreatureTypeId, SpawnEnv, SpawnSlotInit, build_spawn_plan
from crimson.weapons import WeaponId
from grim.rand import Crand


def test_spawn_plan_remaps_ai_links_with_pool_offset() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x13, Vec2(100.0, 200.0), 0.0, rng, env)

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
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x00, Vec2(100.0, 200.0), 0.0, rng, env)

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
            child_template_id=0,
        )
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


def test_spawn_plan_materialization_spawns_burst_fx() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    state = GameplayState(rng=rng)
    pool = CreaturePool(env=env, effects=state.effects)

    plan = build_spawn_plan(1, Vec2(100.0, 200.0), 0.0, rng, env)
    pool.spawn_plan(plan, rand=rng.rand, detail_preset=5)

    active = state.effects.iter_active()
    assert len(active) == 8
    assert all(int(entry.effect_id) == 0 for entry in active)


def test_non_spawner_update_does_not_clamp_offscreen_positions() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.flags = 0
    creature.ai_mode = 0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.pos = Vec2(-64.0, 1088.0)

    pool.update(1.0 / 60.0, state=state, players=[player])

    assert creature.pos.x == pytest.approx(-64.0)
    assert creature.pos.y == pytest.approx(1088.0)


def test_creature_contact_damage_targets_player1_when_player0_is_dead() -> None:
    state = GameplayState()
    pool = CreaturePool()

    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=0.0, weapon_id=int(WeaponId.ASSAULT_RIFLE))
    player1 = PlayerState(index=1, pos=Vec2(110.0, 100.0), health=100.0, weapon_id=int(WeaponId.ASSAULT_RIFLE))

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.flags = 0
    creature.ai_mode = 0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(110.0, 100.0)

    pool.update(1.0 / 60.0, state=state, players=[player0, player1], rand=lambda: 0)

    assert creature.target_player == 1
    assert player0.health == pytest.approx(0.0)
    assert player1.health == pytest.approx(90.0)


def test_creature_retargets_to_closer_player1_in_two_player_mode() -> None:
    state = GameplayState()
    pool = CreaturePool()

    player0 = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=100.0, weapon_id=int(WeaponId.ASSAULT_RIFLE))
    player1 = PlayerState(index=1, pos=Vec2(104.0, 100.0), health=100.0, weapon_id=int(WeaponId.ASSAULT_RIFLE))

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.flags = 0
    creature.ai_mode = 0
    creature.move_speed = 0.0
    creature.size = 45.0
    creature.contact_damage = 10.0
    creature.target_player = 0
    creature.pos = Vec2(104.0, 100.0)

    pool.update(1.0 / 60.0, state=state, players=[player0, player1], rand=lambda: 0)

    assert creature.target_player == 1
    assert player0.health == pytest.approx(100.0)
    assert player1.health == pytest.approx(90.0)


@dataclass
class _StubRand:
    values: list[int]

    def __post_init__(self) -> None:
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self.values):
            value = 0
        else:
            value = int(self.values[self._idx])
        self._idx += 1
        return value


def test_death_awards_xp_and_can_spawn_bonus() -> None:
    state = GameplayState()
    # RNG values:
    # - try_spawn_on_kill gate: (rand % 9) == 1
    # - bonus_pick_random_type roll: roll=1 => points
    # - points amount: (rand & 7) < 3 => 1000
    state.rng = _StubRand([1, 0, 0])  # type: ignore[assignment]

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.ASSAULT_RIFLE))
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
        rand=state.rng.rand,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )
    assert death.xp_awarded == 10
    assert player.experience == 10
    assert any(entry.bonus_id != 0 for entry in state.bonus_pool.entries)
    # Successful spawn-on-kill emits a 16-particle burst (4 RNG draws each).
    assert state.rng._idx == 67  # type: ignore[attr-defined]


def test_death_award_uses_float32_sum_before_truncation() -> None:
    state = GameplayState()
    state.rng = _StubRand([0])  # type: ignore[assignment]

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.ASSAULT_RIFLE))
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
        rand=state.rng.rand,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )
    assert death.xp_awarded == 61
    assert player.experience == 48_902


def test_handle_death_no_freeze_does_not_enqueue_fx_queue_random() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.RUSH)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 0.0
    creature.pos = Vec2(100.0, 100.0)

    fx_queue = FxQueue()
    calls = 0
    orig_add_random = fx_queue.add_random

    def _add_random(**kwargs):  # noqa: ANN003
        nonlocal calls
        calls += 1
        return orig_add_random(**kwargs)

    fx_queue.add_random = _add_random  # type: ignore[method-assign]

    pool.handle_death(
        0,
        state=state,
        players=[player],
        rand=state.rng.rand,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=fx_queue,
    )

    assert calls == 0


def test_handle_death_freeze_enqueues_fx_queue_random_once() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.RUSH)
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 0.0
    creature.pos = Vec2(100.0, 100.0)

    fx_queue = FxQueue()
    calls = 0
    orig_add_random = fx_queue.add_random

    def _add_random(**kwargs):  # noqa: ANN003
        nonlocal calls
        calls += 1
        return orig_add_random(**kwargs)

    fx_queue.add_random = _add_random  # type: ignore[method-assign]

    pool.handle_death(
        0,
        state=state,
        players=[player],
        rand=state.rng.rand,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=fx_queue,
    )

    assert calls == 1


def test_handle_death_inactive_entry_skips_reentrant_side_effects() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.RUSH)
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = False
    creature.hp = -1.0
    creature.reward_value = 49.0
    creature.pos = Vec2(100.0, 100.0)

    fx_queue = FxQueue()
    calls = 0
    orig_add_random = fx_queue.add_random

    def _add_random(**kwargs):  # noqa: ANN003
        nonlocal calls
        calls += 1
        return orig_add_random(**kwargs)

    fx_queue.add_random = _add_random  # type: ignore[method-assign]

    death = pool.handle_death(
        0,
        state=state,
        players=[player],
        rand=state.rng.rand,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=fx_queue,
    )

    assert death.xp_awarded == 0
    assert player.experience == 0
    assert calls == 0
    assert not any(entry.bonus_id != 0 for entry in state.bonus_pool.entries)


def test_spawn_inits_resets_native_spawn_state_fields() -> None:
    pool = CreaturePool()
    (idx,) = pool.spawn_inits(
        [
            CreatureInit(
                origin_template_id=0x99,
                pos=Vec2(100.0, 200.0),
                heading=0.75,
                phase_seed=10.0,
                type_id=CreatureTypeId.ALIEN,
                health=40.0,
                max_health=40.0,
                move_speed=2.0,
                reward_value=12.0,
                size=45.0,
                contact_damage=6.0,
            )
        ]
    )
    entry = pool.entries[idx]

    assert entry.active is True
    assert entry.vel == Vec2()
    assert entry.force_target == 0
    assert entry.attack_cooldown == pytest.approx(0.0, abs=1e-9)
    assert entry.collision_timer == pytest.approx(0.0, abs=1e-9)
    assert entry.hit_flash_timer == pytest.approx(0.0, abs=1e-9)
    assert entry.anim_phase == pytest.approx(0.0, abs=1e-9)
    assert entry.last_hit_owner_id == -100


def test_spawn_init_preserves_stale_link_index_for_implicit_ai7_timer() -> None:
    pool = CreaturePool()
    pool.entries[0].link_index = -1

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x75,
            pos=Vec2(1064.0, 392.0),
            heading=0.0,
            phase_seed=0.0,
            type_id=CreatureTypeId.SPIDER_SP1,
            flags=CreatureFlags.AI7_LINK_TIMER,
            ai_mode=0,
            health=54.0,
            max_health=54.0,
            move_speed=1.17,
            reward_value=0.0,
            size=56.0,
            contact_damage=5.0,
        )
    )

    assert idx == 0
    assert pool.entries[idx].link_index == -1


def test_spawn_init_ai_timer_still_overrides_link_index() -> None:
    pool = CreaturePool()
    pool.entries[0].link_index = -1

    idx = pool.spawn_init(
        CreatureInit(
            origin_template_id=0x38,
            pos=Vec2(1064.0, 392.0),
            heading=0.0,
            phase_seed=0.0,
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
        )
    )

    assert idx == 0
    assert pool.entries[idx].link_index == 0


def test_tick_dead_defers_corpse_deactivation_until_post_render_cleanup() -> None:
    pool = CreaturePool()
    corpse = pool.entries[6]
    corpse.active = True
    corpse.hp = -231.675
    corpse.hitbox_size = -9.656
    corpse.pos = Vec2(588.6516, 379.7685)
    corpse.flags = CreatureFlags.AI7_LINK_TIMER

    pool._tick_dead(  # noqa: SLF001 - validate native timing detail.
        corpse,
        dt=0.018,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue_rotated=None,
    )

    assert corpse.active is True
    assert corpse.hitbox_size == pytest.approx(-10.016, abs=1e-6)

    pool.finalize_post_render_lifecycle()
    assert corpse.active is False


def test_dead_self_damage_tick_flags_still_shrink_hitbox_before_dead_decay() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.PISTOL))
    pool = CreaturePool()

    corpse = pool.entries[42]
    corpse.active = True
    corpse.hp = -0.08500146865844727
    corpse.hitbox_size = 12.640003204345703
    corpse.flags = CreatureFlags.SELF_DAMAGE_TICK

    # 38 ms frame from gameplay_diff_capture tick 3636.
    pool.update(0.03800000250339508, state=state, players=[player], rand=lambda: 0)

    # Native applies SELF_DAMAGE_TICK via creature_apply_damage even while hp<=0.
    assert corpse.hitbox_size == pytest.approx(11.006003, abs=1e-5)


def test_spawn_allocation_uses_slot_still_active_until_post_render_cleanup() -> None:
    pool = CreaturePool(size=24)
    for idx in range(22):
        entry = pool.entries[idx]
        entry.active = True
        entry.hp = 1.0
        entry.hitbox_size = CREATURE_HITBOX_ALIVE
        entry.pos = Vec2(float(idx), 0.0)

    corpse = pool.entries[6]
    corpse.hp = -231.675
    corpse.hitbox_size = -9.656
    corpse.pos = Vec2(588.6516, 379.7685)
    corpse.flags = CreatureFlags.AI7_LINK_TIMER

    pool.entries[22].active = False
    pool.entries[22].hitbox_size = -10.21
    pool.entries[22].hp = -45.9623

    pool._tick_dead(  # noqa: SLF001 - validate native timing detail.
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
            phase_seed=17.0,
            type_id=CreatureTypeId.LIZARD,
            health=60.6925,
            max_health=60.6925,
            move_speed=1.0,
            reward_value=0.0,
            size=50.0,
            contact_damage=4.0,
        )
    )
    assert spawned_idx == 22


def test_ai7_link_timer_uses_rounded_frame_dt_ms_for_boundary_crossing() -> None:
    state = GameplayState(rng=Crand(0xBEEF))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), weapon_id=int(WeaponId.PISTOL))
    pool = CreaturePool()

    creature = pool.entries[0]
    creature.active = True
    creature.hp = 50.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.flags = CreatureFlags.AI7_LINK_TIMER
    creature.ai_mode = 0
    creature.link_index = -33
    creature.target_player = 0
    creature.pos = Vec2(640.0, 512.0)
    creature.move_speed = 0.0
    creature.size = 45.0

    # 0.0329999998s is captured as frame_dt_ms_i32=33 in native traces.
    dt = 0.032999999821186066
    stub_rand = _StubRand([0x11])
    pool.update(dt, state=state, players=[player], rand=stub_rand.rand)

    assert creature.ai_mode == 7
    assert creature.link_index == 517

    pool.finalize_post_render_lifecycle()
    assert pool.entries[6].active is False
