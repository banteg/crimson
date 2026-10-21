"""Gameplay regressions for the opt-out original-bug fixes in rules 2."""

import math

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.damage_types import CreatureDamageType
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.game_modes import GameMode
from crimson.gameplay import _player_tick_perks
from crimson.math_parity import f32, x87_pc24_mul
from crimson.perks import PerkId
from crimson.projectiles.runtime.collision import creature_find_nearest_active, creature_find_nearest_alive
from crimson.projectiles.types import SecondaryProjectileTypeId
from crimson.quests.results import compute_quest_final_time
from crimson.sim.state_types import WeaponSlot
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, player_input, step_creatures, step_player


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize(
    "perk,name,count", [(PerkId.FIRE_CAUGH, "fire_cough", 1), (PerkId.HOT_TEMPERED, "hot_tempered", 8)],
)
def test_each_player_can_fire_a_due_perk(rules, preserve_bugs, perk, name, count):
    legacy = preserve_bugs or rules == 1
    world = make_world(player_count=2, preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.perks[perk] = 1
    for player in world.players:
        setattr(player, name + "_timer", f32(1.5))
        player.aim = player.pos + Vec2(100, 0)
        _player_tick_perks(player, world.state, world.players, f32(0.01))
    assert sum(p.active for p in world.state.projectiles.entries) == count * (1 if legacy else 2)
    if not legacy:
        assert getattr(world.state.perk_intervals, name) == f32(1.4)
        assert all(getattr(p, name + "_interval") >= 2 for p in world.players)
        assert all(getattr(p, name + "_timer") < 0.2 for p in world.players)


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
def test_simultaneous_coop_weapon_swaps(rules, preserve_bugs):
    legacy = preserve_bugs or rules == 1
    world = make_world(player_count=2, preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.perks[PerkId.ALTERNATE_WEAPON] = 1
    for player in world.players:
        weapon_assign_player(player, WeaponId.ASSAULT_RIFLE, state=world.state)
        player.alt_weapon = WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=12, ammo=12)
        step_player(world, player, player_input(reload_pressed=True), 0.01)
    assert [p.weapon.weapon_id for p in world.players] == [
        WeaponId.PISTOL,
        WeaponId.ASSAULT_RIFLE if legacy else WeaponId.PISTOL,
    ]
    if not legacy:
        assert [p.alt_weapon_swap_cooldown_ms for p in world.players] == [200, 200]
        step_player(world, world.players[1], player_input(), 0.01)
        assert [p.alt_weapon_swap_cooldown_ms for p in world.players] == [200, 0]


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize("health", [[100, -80], [-80, 100]])
def test_dead_partner_cannot_reduce_life_bonus(rules, preserve_bugs, health):
    legacy = preserve_bugs or rules == 1
    result = compute_quest_final_time(
        base_time_ms=100000, player_health_values=health, pending_perk_count=2, preserve_bugs=preserve_bugs, rules=rules,
    )
    assert result.life_bonus_ms == (1000 if legacy else 5000)
    assert result.final_time_ms == (97000 if legacy else 93000)


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize("split", [False, True])
def test_rocket_rewards_and_splits_once(rules, preserve_bugs, split):
    legacy = preserve_bugs or rules == 1
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.game_mode = GameMode.RUSH
    world.creatures.entries[0] = CreatureState(
        active=True,
        hp=1,
        max_hp=100,
        reward_value=100,
        pos=Vec2(513, 512),
        size=50,
        flags=CreatureFlags.SPLIT_ON_DEATH if split else CreatureFlags(0),
    )
    rocket = world.state.secondary_projectiles.entries[0]
    rocket.active = True
    rocket.type_id = SecondaryProjectileTypeId.DETONATION
    rocket.pos = Vec2(512, 512)
    rocket.detonation_scale = 0.5
    rocket.detonation_t = 0.5
    runtime = make_step_runtime(world, dt=1 / 60)
    world.state.secondary_projectiles.step(runtime)
    assert world.players[0].experience == (200 if legacy else 100)
    assert len(runtime.deaths) == (2 if legacy else 1)
    assert sum(c.active and c.hp > 0 for c in world.creatures.entries) == ((4 if legacy else 2) if split else 0)


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize("hp,timer", [(-1, 10), (100, 10), (0, 16)])
def test_chain_skips_corpses(rules, preserve_bugs, hp, timer):
    legacy = preserve_bugs or rules == 1
    entries = [
        CreatureState(active=True, hp=hp, death_timer=timer, pos=Vec2(30, 0)),
        CreatureState(active=True, hp=100, pos=Vec2(60, 0)),
    ]
    assert creature_find_nearest_active(
        creatures=entries, origin=Vec2(), exclude_id=2, min_dist=10, preserve_bugs=preserve_bugs, rules=rules,
    ) == (0 if legacy else 1)
    assert creature_find_nearest_alive(creatures=entries, origin=Vec2(), preserve_bugs=preserve_bugs, rules=rules) == (
        0 if legacy and timer == 16 else 1
    )
    entries[1].active = False
    if not legacy:
        assert creature_find_nearest_active(creatures=entries, origin=Vec2(), exclude_id=2, min_dist=10) == -1


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize("perk", [PerkId.PLAGUEBEARER, PerkId.RADIOACTIVE])
@pytest.mark.parametrize("exact", [False, True])
def test_dot_death_rewards_and_stops_ranged_fire(rules, preserve_bugs, perk, exact):
    legacy = preserve_bugs or rules == 1
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.game_mode = GameMode.RUSH
    world.state.perks[perk] = 1
    hp = 15.0 if perk == PerkId.PLAGUEBEARER else x87_pc24_mul(20.0, f32(0.3))
    creature = CreatureState(
        active=True,
        hp=hp if exact else 1,
        max_hp=hp,
        reward_value=100,
        pos=world.players[0].pos + Vec2(80, 0),
        move_speed=0,
        dot_tick_timer=-1,
        plague_infected=perk == PerkId.PLAGUEBEARER,
        flags=CreatureFlags.RANGED_PLASMA_RIFLE,
        type_id=CreatureTypeId.ALIEN,
    )
    world.creatures.entries[0] = creature
    step_creatures(world, 0.01)
    assert creature.hp <= 0
    assert world.players[0].experience == (0 if legacy and exact else 100)
    assert sum(p.active for p in world.state.projectiles.entries) == (1 if legacy else 0)


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
@pytest.mark.parametrize("direction", [Vec2(1, 0), Vec2(-1, 0), Vec2(0, 1), Vec2(0, -1), Vec2()])
def test_lethal_impact_controls_slide_direction(rules, preserve_bugs, direction):
    legacy = preserve_bugs or rules == 1
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.game_mode = GameMode.RUSH
    creature = CreatureState(active=True, hp=1, heading=0.7, pos=Vec2(500, 500))
    world.creatures.entries[0] = creature
    creature_apply_damage(make_step_runtime(world, dt=0.01), 0, 2, CreatureDamageType.EXPLOSION, direction)
    if legacy or direction == Vec2():
        assert creature.heading == 0.7
    else:
        travel = Vec2(-math.cos(creature.heading - math.pi / 2), -math.sin(creature.heading - math.pi / 2))
        assert travel.x == pytest.approx(direction.x, abs=1e-6)
        assert travel.y == pytest.approx(direction.y, abs=1e-6)


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
def test_nuke_aligns_new_deaths_outward_without_rotating_existing_corpses(rules, preserve_bugs):
    legacy = preserve_bugs or rules == 1
    from crimson.bonuses import BonusId
    from crimson.bonuses.apply import bonus_apply

    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.game_mode = GameMode.RUSH
    for index, hp in enumerate((1, -1)):
        world.creatures.entries[index] = CreatureState(active=True, hp=hp, heading=0.7, pos=Vec2(562, 512))
    bonus_apply(
        world.state,
        world.players[0],
        BonusId.NUKE,
        amount=1,
        step_runtime=make_step_runtime(world),
        origin=Vec2(512, 512),
        creatures=world.creatures.entries,
        players=world.players,
    )
    assert world.creatures.entries[0].heading == (0.7 if legacy else f32(-math.pi / 2))
    assert world.creatures.entries[1].heading == 0.7


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
def test_radioactive_keeps_lizard_exception_at_zero_hp(rules, preserve_bugs):
    legacy = preserve_bugs or rules == 1
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.perks[PerkId.RADIOACTIVE] = 1
    creature = CreatureState(
        active=True,
        hp=x87_pc24_mul(20.0, f32(0.3)),
        pos=world.players[0].pos + Vec2(80, 0),
        move_speed=0,
        dot_tick_timer=-1,
        type_id=CreatureTypeId.LIZARD,
    )
    world.creatures.entries[0] = creature
    step_creatures(world, 0.01)
    assert creature.hp == (0 if legacy else 1)
    assert world.players[0].experience == 0


def test_primary_impulse_uses_sine_for_the_vertical_component():
    import json
    import struct
    from pathlib import Path

    from tests.support.primary_impact import observe

    case = json.loads(Path("tests/fixtures/native/primary-impact-presentation.json").read_text())[0]["input"]
    case["primary"][0]["angle"] = 0.0  # straight up
    case["creatures"][0]["x"] = case["primary"][0]["x"]
    case["creatures"][0]["y"] = case["primary"][0]["y"] - 20
    old = observe(case)
    fixed = observe(case, preserve_bugs=False)
    assert old["damage_calls"][0][3][0] == old["damage_calls"][0][3][1]
    impulse = struct.unpack("<2f", struct.pack("<2I", *fixed["damage_calls"][0][3]))
    assert impulse[0] == pytest.approx(0, abs=1e-6)
    assert impulse[1] == -case["primary"][0]["speed"]


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
def test_split_children_keep_pre_impact_heading(rules, preserve_bugs):
    from crimson.math_parity import NATIVE_HALF_PI, x87_pc24_add, x87_pc24_sub

    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    world.state.game_mode = GameMode.RUSH
    parent = CreatureState(
        active=True, hp=1, max_hp=100, size=50, heading=f32(0.7), pos=Vec2(500, 500), flags=CreatureFlags.SPLIT_ON_DEATH,
    )
    world.creatures.entries[0] = parent
    creature_apply_damage(make_step_runtime(world, dt=0.01), 0, 2, CreatureDamageType.EXPLOSION, Vec2(1, 0))
    children = [c for c in world.creatures.entries[1:] if c.active]
    assert [c.heading for c in children] == [
        x87_pc24_sub(f32(0.7), NATIVE_HALF_PI),
        x87_pc24_add(f32(0.7), NATIVE_HALF_PI),
    ]


@pytest.mark.parametrize(
    "flags", [CreatureFlags(0), CreatureFlags.SPAWNER, CreatureFlags.SPAWNER | CreatureFlags.SPAWNER_MOBILE],
)
def test_impact_alignment_retains_spawner_slide_eligibility(flags):
    world = make_world()
    world.state.game_mode = GameMode.RUSH
    creature = CreatureState(active=True, hp=1, pos=Vec2(500, 500), flags=flags)
    world.creatures.entries[0] = creature
    creature_apply_damage(make_step_runtime(world, dt=0.01), 0, 2, CreatureDamageType.EXPLOSION, Vec2(1, 0))
    step_creatures(world, 0.01)
    assert (creature.pos.x > 500) == (flags != CreatureFlags.SPAWNER)
    assert creature.pos.y == pytest.approx(500, abs=1e-4)
