from __future__ import annotations

import math

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.math_parity import NATIVE_HALF_PI, NATIVE_PI, x87_pc24_sub
from crimson.projectiles.runtime import (
    PrimaryStepCtx,
    SecondaryProjectilePool,
    SecondarySpawnSpec,
    SecondaryStepCtx,
)
from crimson.projectiles.types import SecondaryProjectileTypeId
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import (
    make_creature_state,
    make_projectile_update_options,
    make_step_runtime,
    place_creatures,
)


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
    world = make_world(preserve_bugs=preserve_bugs)
    state, pool = world.state, world.state.projectiles
    player = world.players[0]
    player.pos = Vec2()
    creatures = place_creatures(world, [make_creature_state(pos=Vec2(50.0, 0.0), active=False)])

    bonus_apply(
        state,
        player,
        BonusId.SHOCK_CHAIN,
        step_runtime=make_step_runtime(world),
        origin=player.pos,
        creatures=creatures,
        players=world.players,
    )

    assert state.shock_chain_links_left == expected_links_left
    assert sfx_ids(state.sfx_queue) == expected_sfx
    assert sum(1 for entry in pool.entries if entry.active) == expected_projectile_count
    if preserve_bugs:
        assert state.shock_chain_projectile_id >= 0
    else:
        assert state.shock_chain_projectile_id == -1


def test_shock_chain_uses_native_f32_nearest_ordering() -> None:
    world = make_world()
    state, pool = world.state, world.state.projectiles
    player = world.players[0]
    player.pos = Vec2()
    first_pos = Vec2(-1727.156494140625, -1351.4605712890625)
    creatures = place_creatures(
        world,
        [
            make_creature_state(pos=first_pos, hp=100.0),
            make_creature_state(pos=Vec2(1722.1292724609375, -1357.8604736328125), hp=100.0),
        ],
    )

    bonus_apply(
        state,
        player,
        BonusId.SHOCK_CHAIN,
        step_runtime=make_step_runtime(world),
        origin=player.pos,
        creatures=creatures,
        players=world.players,
    )

    projectile = pool.entries[state.shock_chain_projectile_id]
    # fpatan stays wide; each PC=24 fsub rounds (bonus_apply 0x00409e0b).
    expected_angle = x87_pc24_sub(x87_pc24_sub(math.atan2(first_pos.y, first_pos.x), NATIVE_HALF_PI), NATIVE_PI)
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
    world = make_world(preserve_bugs=preserve_bugs)
    state, pool = world.state, world.state.projectiles
    player = world.players[0]
    player.pos = Vec2()
    creatures = place_creatures(
        world,
        [
            make_creature_state(pos=Vec2(200.0, 0.0), active=False),
            make_creature_state(pos=Vec2(50.0, 0.0), hp=100.0),
        ],
    )
    step_runtime = make_step_runtime(world)

    bonus_apply(
        state,
        player,
        BonusId.SHOCK_CHAIN,
        step_runtime=step_runtime,
        origin=player.pos,
        creatures=creatures,
        players=world.players,
    )
    first_proj = int(state.shock_chain_projectile_id)
    assert first_proj >= 0

    for _ in range(2):
        pool.step(
            PrimaryStepCtx(
                dt=0.1,
                creatures=creatures,
                options=make_projectile_update_options(world, step_runtime=step_runtime),
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
    world = make_world(preserve_bugs=preserve_bugs)
    state, pool = world.state, world.state.secondary_projectiles
    creatures = place_creatures(world, [make_creature_state(pos=Vec2(100.0, 0.0), active=False)])

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
            step_runtime=make_step_runtime(world),
            dt=0.01,
            creatures=creatures,
            runtime_state=state,
        ),
    )

    assert pool.entries[idx].target_id == expected_target_id
