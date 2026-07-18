from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.bonuses.update import bonus_telekinetic_update
from crimson.creatures.runtime import CreaturePool
from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_telekinetic_picks_up_bonus_after_hover_time() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert entry is not None

    base_player = PlayerState(index=0, pos=Vec2(), aim=Vec2(100.0, 100.0))
    assert bonus_telekinetic_update(state, [base_player], dt=0.7, creatures=[]) == []
    assert entry.picked is False

    perk_player = PlayerState(index=0, pos=Vec2(), aim=Vec2(100.0, 100.0))
    perk_player.perk_counts[int(PerkId.TELEKINETIC)] = 1
    pickups = bonus_telekinetic_update(state, [perk_player], dt=0.7, creatures=[])

    assert len(pickups) == 1
    assert entry.picked is True
    assert perk_player.experience == 500


@pytest.mark.parametrize(
    ("preserve_bugs", "perk_player_index", "expected_pickup"),
    [
        (True, 0, True),
        (True, 1, False),
        (False, 1, True),
    ],
    ids=["native-primary-owner", "native-secondary-owner", "corrected-secondary-owner"],
)
def test_telekinetic_player_ownership(
    preserve_bugs: bool,
    perk_player_index: int,
    expected_pickup: bool,
) -> None:
    state = GameplayState(preserve_bugs=preserve_bugs)
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert entry is not None

    players = [
        PlayerState(index=0, pos=Vec2(), aim=Vec2()),
        PlayerState(index=1, pos=Vec2(), aim=Vec2(100.0, 100.0)),
    ]
    players[perk_player_index].perk_counts[int(PerkId.TELEKINETIC)] = 1

    pickups = bonus_telekinetic_update(state, players, dt=0.7, creatures=[])

    assert entry.picked is expected_pickup
    assert bool(pickups) is expected_pickup
    if expected_pickup:
        assert pickups[0].player_index == 1
    assert players[0].experience == (500 if expected_pickup else 0)
    assert players[1].experience == 0


def test_telekinetic_nuke_origin_is_bonus_position() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.NUKE, state=state)
    assert entry is not None

    player = PlayerState(index=0, pos=Vec2(), aim=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.TELEKINETIC)] = 1

    bonus_telekinetic_update(state, [player], dt=0.7, creatures=[], detail_preset=5)

    active = [proj for proj in state.projectiles.entries if proj.active]
    assert active
    for proj in active:
        assert_float_close(proj.pos.x, 100.0)
        assert_float_close(proj.pos.y, 100.0)


def test_telekinetic_shock_chain_origin_is_bonus_position() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.SHOCK_CHAIN, state=state)
    assert entry is not None

    player = PlayerState(index=0, pos=Vec2(), aim=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.TELEKINETIC)] = 1

    pool = CreaturePool()
    target = pool.entries[0]
    target.active = True
    target.pos = Vec2(140.0, 100.0)
    target.hp = 10.0
    target.max_hp = 10.0

    bonus_telekinetic_update(state, [player], dt=0.7, creatures=pool.entries, detail_preset=5)

    proj_id = int(state.shock_chain_projectile_id)
    assert proj_id != -1
    proj = state.projectiles.entries[proj_id]
    assert_float_close(proj.pos.x, 100.0)
    assert_float_close(proj.pos.y, 100.0)


def test_telekinetic_picks_only_one_bonus_per_frame_across_players() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    first = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    second = state.bonus_pool.spawn_at(pos=Vec2(200.0, 200.0), bonus_id=BonusId.POINTS, state=state)
    assert first is not None
    assert second is not None

    player0 = PlayerState(index=0, pos=Vec2(), aim=Vec2(100.0, 100.0))
    player1 = PlayerState(index=1, pos=Vec2(), aim=Vec2(200.0, 200.0))
    player0.perk_counts[int(PerkId.TELEKINETIC)] = 1
    player1.perk_counts[int(PerkId.TELEKINETIC)] = 1

    pickups = bonus_telekinetic_update(state, [player0, player1], dt=0.7, creatures=[])

    assert len(pickups) == 1
    assert pickups[0].player_index == 0
    assert first.picked is True
    assert second.picked is False


def test_telekinetic_hover_timer_carries_across_bonus_switch() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    first = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    second = state.bonus_pool.spawn_at(pos=Vec2(130.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert first is not None
    assert second is not None

    player = PlayerState(index=0, pos=Vec2(), aim=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.TELEKINETIC)] = 1

    assert bonus_telekinetic_update(state, [player], dt=0.4, creatures=[]) == []
    assert first.picked is False
    assert second.picked is False

    player.aim = Vec2(130.0, 100.0)
    pickups = bonus_telekinetic_update(state, [player], dt=0.3, creatures=[])

    assert len(pickups) == 1
    assert pickups[0].bonus_id == BonusId.POINTS
    assert_float_close(pickups[0].pos.x, 130.0)
    assert_float_close(pickups[0].pos.y, 100.0)
    assert first.picked is False
    assert second.picked is True
