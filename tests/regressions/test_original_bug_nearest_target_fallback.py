from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import (
    make_creature_state,
    make_step_runtime,
    place_creatures,
)


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_projectile_count", "expected_links_left", "expected_sfx"),
    [
        (False, 0, 0, [SfxId.UI_BONUS]),
        (True, 1, 0x20, [SfxId.UI_BONUS, SfxId.SHOCK_HIT_01]),
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
        amount=1,
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
