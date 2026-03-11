from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.creatures.runtime import CreaturePool
from crimson.gameplay import GameplayState
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_nuke_damage_is_limited_to_radius() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    pool = CreaturePool()
    near = pool.entries[0]
    near.active = True
    near.pos = player.pos + Vec2(100.0, 0.0)
    near.hp = 10.0
    near.max_hp = 10.0

    far = pool.entries[1]
    far.active = True
    far.pos = player.pos + Vec2(300.0, 0.0)
    far.hp = 10.0
    far.max_hp = 10.0

    bonus_apply(
        state,
        player,
        BonusId.NUKE,
        origin=player.pos,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
    )

    assert near.hp <= 0.0
    assert far.hp == 10.0


def test_nuke_spawns_projectiles_with_weapon_meta_speed() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    bonus_apply(state, player, BonusId.NUKE, origin=player.pos, creatures=[], players=[player], detail_preset=5)

    active = [entry for entry in state.projectiles.entries if entry.active]

    pistol = [entry for entry in active if entry.type_id == int(ProjectileTemplateId.PISTOL)]
    assert len(pistol) == 4
    for entry in pistol:
        assert_float_close(entry.travel_budget, 55.0)
        assert_float_close(entry.speed_scale, 0.5)

    gauss = [entry for entry in active if entry.type_id == int(ProjectileTemplateId.GAUSS_GUN)]
    assert len(gauss) == 2
    for entry in gauss:
        assert_float_close(entry.travel_budget, 215.0)
        assert_float_close(entry.speed_scale, 1.0)
