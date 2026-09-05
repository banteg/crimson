from __future__ import annotations

import math

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.math_parity import NATIVE_HALF_PI, NATIVE_PI, f32
from crimson.projectiles.runtime import (
    PrimaryStepCtx,
    ProjectilePool,
    SecondaryProjectilePool,
    SecondarySpawnSpec,
    SecondaryStepCtx,
)
from crimson.projectiles.types import SecondaryProjectileTypeId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.factories import RecordingCreatureDamageRuntime, make_creature_state, make_projectile_update_options
from tests.support.helpers import ScriptedCrand


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_projectile_count", "expected_links_left", "expected_sfx"),
    [
        (False, 0, 0, []),
        (True, 1, 0x20, [SfxId.SHOCK_HIT_01]),
    ],
    ids=["default-noops-without-target", "preserve-bugs-falls-back-to-slot0"],
)
def test_shock_chain_initial_target_miss_handling(
    preserve_bugs: bool,
    expected_projectile_count: int,
    expected_links_left: int,
    expected_sfx: list[str],
) -> None:
    pool = ProjectilePool(size=4)
    state = GameplayState(projectiles=pool, preserve_bugs=preserve_bugs)
    player = PlayerState(index=0, pos=Vec2())
    creatures = [make_creature_state(pos=Vec2(50.0, 0.0), active=False)]

    bonus_apply(
        state,
        player,
        BonusId.SHOCK_CHAIN,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=creatures),
        origin=player.pos,
        creatures=creatures,
        players=[player],
    )

    assert state.shock_chain_links_left == expected_links_left
    assert state.sfx_queue == expected_sfx
    assert sum(1 for entry in pool.entries if entry.active) == expected_projectile_count
    if preserve_bugs:
        assert state.shock_chain_projectile_id >= 0
    else:
        assert state.shock_chain_projectile_id == -1


def test_shock_chain_uses_native_f32_nearest_ordering() -> None:
    pool = ProjectilePool(size=4)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2())
    first_pos = Vec2(-1727.156494140625, -1351.4605712890625)
    creatures = [
        make_creature_state(pos=first_pos, hp=100.0),
        make_creature_state(pos=Vec2(1722.1292724609375, -1357.8604736328125), hp=100.0),
    ]

    bonus_apply(
        state,
        player,
        BonusId.SHOCK_CHAIN,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=creatures),
        origin=player.pos,
        creatures=creatures,
        players=[player],
    )

    projectile = pool.entries[state.shock_chain_projectile_id]
    expected_angle = f32(math.atan2(first_pos.y, first_pos.x) - NATIVE_HALF_PI - NATIVE_PI)
    assert projectile.angle == expected_angle


@pytest.mark.parametrize(
    ("preserve_bugs", "expect_new_segment"),
    [
        (False, False),
        (True, True),
    ],
    ids=["default-stops-chain-without-next-target", "preserve-bugs-retargets-to-slot0"],
)
def test_shock_chain_retarget_miss_handling(preserve_bugs: bool, expect_new_segment: bool) -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool, preserve_bugs=preserve_bugs)
    player = PlayerState(index=0, pos=Vec2())
    creatures = [
        make_creature_state(pos=Vec2(200.0, 0.0), active=False),
        make_creature_state(pos=Vec2(50.0, 0.0), hp=100.0),
    ]

    bonus_apply(
        state,
        player,
        BonusId.SHOCK_CHAIN,
        creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=creatures),
        origin=player.pos,
        creatures=creatures,
        players=[player],
    )
    first_proj = int(state.shock_chain_projectile_id)
    assert first_proj >= 0

    for _ in range(2):
        pool.step(
            PrimaryStepCtx(
                dt=0.1,
                creatures=creatures,
                options=make_projectile_update_options(
                    creatures=creatures,
                    world_size=1024.0,
                    rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                    runtime_state=state,
                ),
            ),
        )

    assert state.shock_chain_links_left == 0x1F
    if expect_new_segment:
        assert state.shock_chain_projectile_id != first_proj
        assert sum(1 for entry in pool.entries if entry.active) >= 2
    else:
        assert state.shock_chain_projectile_id == first_proj
        assert sum(1 for entry in pool.entries if entry.active) == 1


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_target_id"),
    [
        (False, -1),
        (True, 0),
    ],
    ids=["default-uses-no-target-sentinel", "preserve-bugs-falls-back-to-slot0"],
)
def test_seeker_spawn_target_miss_handling(preserve_bugs: bool, expected_target_id: int) -> None:
    pool = SecondaryProjectilePool(size=1)
    creatures = [make_creature_state(pos=Vec2(100.0, 0.0), active=False)]

    idx = pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
            creatures=creatures,
            preserve_bugs=preserve_bugs,
        ),
    )

    assert pool.entries[idx].target_id == expected_target_id


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_target_id"),
    [
        (False, -1),
        (True, 0),
    ],
    ids=["default-keeps-no-target-sentinel", "preserve-bugs-reuses-slot0"],
)
def test_seeker_retarget_miss_handling(preserve_bugs: bool, expected_target_id: int) -> None:
    pool = SecondaryProjectilePool(size=1)
    creatures = [make_creature_state(pos=Vec2(100.0, 0.0), active=False)]
    state = GameplayState(secondary_projectiles=pool, preserve_bugs=preserve_bugs)

    idx = pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
        ),
    )
    pool.entries[idx].target_id = 0

    pool.step(
        SecondaryStepCtx(
            creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=creatures),
            dt=0.01,
            creatures=creatures,
            runtime_state=state,
        ),
    )

    assert pool.entries[idx].target_id == expected_target_id
