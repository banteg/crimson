from __future__ import annotations

from grim.geom import Vec2

from dataclasses import dataclass

import pytest

from crimson.gameplay import GameplayState, PlayerState
from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.creatures.spawn import SpawnEnv, SpawnSlotInit, build_spawn_plan
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
    plan = build_spawn_plan(0x13, (100.0, 200.0), 0.0, rng, env)

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
    plan = build_spawn_plan(0x00, (100.0, 200.0), 0.0, rng, env)

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

    plan = build_spawn_plan(1, (100.0, 200.0), 0.0, rng, env)
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
    creature.pos.x = -64.0
    creature.pos.y = 1088.0

    pool.update(1.0 / 60.0, state=state, players=[player])

    assert creature.pos.x == pytest.approx(-64.0)
    assert creature.pos.y == pytest.approx(1088.0)


@dataclass
class _StubRand:
    values: list[int]

    def __post_init__(self) -> None:
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self.values):
            return 0
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
    creature.pos.x = 100.0
    creature.pos.y = 100.0
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
