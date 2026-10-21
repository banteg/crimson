"""Rules-2 conversions retain full volleys, normal cadence and free bonus ammo."""

from itertools import pairwise

import pytest

from crimson.math_parity import f32, x87_pc24_mul
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon, player_input, step_player


@pytest.mark.parametrize("weapon,count,legacy_count", [(WeaponId.GAUSS_SHOTGUN, 6, 1), (WeaponId.MULTI_PLASMA, 5, 3)])
@pytest.mark.parametrize("rules,preserve", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize("bonus", [False, True])
@pytest.mark.parametrize("perk", [None, PerkId.FASTSHOT, PerkId.SHARPSHOOTER])
def test_conversion_policy(weapon, count, legacy_count, rules, preserve, bonus, perk):
    world = make_world(preserve_bugs=preserve)
    state = world.state
    state.rules = rules
    state.rng = RecordingCrand(Crand(123))
    player = world.players[0]
    weapon_assign_player(player, weapon, state=state)
    if perk is not None:
        state.perks[perk] = 1
    player.fire_bullets_timer = 10 if bonus else 0
    before = player.weapon.ammo
    fire_player_weapon(world, player, player_input(fire_down=True, aim=player.pos + Vec2(200, 0)), 1 / 60)
    expected_count = legacy_count if bonus and (preserve or rules == 1) else count
    projectiles = [p for p in state.projectiles.entries if p.active]
    assert len(projectiles) == expected_count
    assert state.shots_fired == expected_count
    assert state.weapon_shots_fired[0][weapon] == expected_count
    assert player.weapon.ammo == before - (0 if bonus else 1)
    cooldown = f32(0.14 if bonus and expected_count == 1 else WEAPON_BY_ID[weapon].shot_cooldown)
    if perk == PerkId.FASTSHOT:
        cooldown = x87_pc24_mul(cooldown, f32(0.88))
    elif perk == PerkId.SHARPSHOOTER:
        cooldown = x87_pc24_mul(cooldown, f32(1.05))
    assert player.weapon.shot_cooldown == cooldown
    jitter = [r for r in state.rng.records_since() if r.caller == RngCallerStatic.PLAYER_UPDATE_FIRE_BULLETS_PELLET_JITTER]
    assert len(jitter) == (expected_count if bonus else 0)
    if bonus:
        assert all(p.type_id == ProjectileTemplateId.FIRE_BULLETS for p in projectiles)
    assert WEAPON_BY_ID[weapon].pellet_count == legacy_count


@pytest.mark.parametrize("weapon,count,cooldown", [(WeaponId.GAUSS_SHOTGUN, 6, 1.05), (WeaponId.MULTI_PLASMA, 5, 0.6208117)])
def test_repeated_conversion_with_full_projectile_pool(weapon, count, cooldown):
    world = make_world()
    player = world.players[0]
    weapon_assign_player(player, weapon, state=world.state)
    player.fire_bullets_timer = 10
    ammo = player.weapon.ammo
    for projectile in world.state.projectiles.entries:
        projectile.active = True
    fired = []
    for tick in range(180):
        before = world.state.shots_fired
        step_player(world, player, player_input(fire_down=True, aim=player.pos + Vec2(200, 0)), 1 / 60)
        if world.state.shots_fired != before:
            assert world.state.shots_fired - before == count
            fired.append(tick)
    assert len(fired) >= 3
    assert all(cooldown - 1e-6 <= (b - a) / 60 <= cooldown + 1 / 60 + 1e-6 for a, b in pairwise(fired))
    assert player.weapon.ammo == ammo
