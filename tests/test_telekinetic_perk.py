from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.bonuses import BonusId
from crimson.creatures.runtime import CreaturePool
from crimson.gameplay import BonusPool, GameplayState, PlayerState, bonus_telekinetic_update
from crimson.perks import PerkId


def test_telekinetic_picks_up_bonus_after_hover_time() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert entry is not None

    base_player = PlayerState(index=0, pos=Vec2(0.0, 0.0), aim_x=100.0, aim_y=100.0)
    assert bonus_telekinetic_update(state, [base_player], dt=0.7) == []
    assert entry.picked is False

    perk_player = PlayerState(index=0, pos=Vec2(0.0, 0.0), aim_x=100.0, aim_y=100.0)
    perk_player.perk_counts[int(PerkId.TELEKINETIC)] = 1
    pickups = bonus_telekinetic_update(state, [perk_player], dt=0.7)

    assert len(pickups) == 1
    assert entry.picked is True
    assert perk_player.experience == 500


def test_telekinetic_nuke_origin_is_bonus_position() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.NUKE, state=state)
    assert entry is not None

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), aim_x=100.0, aim_y=100.0)
    player.perk_counts[int(PerkId.TELEKINETIC)] = 1

    bonus_telekinetic_update(state, [player], dt=0.7, detail_preset=5)

    active = [proj for proj in state.projectiles.entries if proj.active]
    assert active
    assert all(math.isclose(proj.pos.x, 100.0, abs_tol=1e-9) for proj in active)
    assert all(math.isclose(proj.pos.y, 100.0, abs_tol=1e-9) for proj in active)


def test_telekinetic_shock_chain_origin_is_bonus_position() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.SHOCK_CHAIN, state=state)
    assert entry is not None

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), aim_x=100.0, aim_y=100.0)
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
    assert math.isclose(proj.pos.x, 100.0, abs_tol=1e-9)
    assert math.isclose(proj.pos.y, 100.0, abs_tol=1e-9)
