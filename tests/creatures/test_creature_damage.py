from __future__ import annotations

from crimson.creatures.damage import (
    creature_apply_damage,
    resolve_native_death_sfx,
)
from crimson.creatures.damage_types import CreatureDamageType
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects_atlas import EffectId
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.factories import make_step_runtime, world_with_creature
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression


def test_damage_type1_heading_jitter_uses_rand_without_player_attacker() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0, flags=CreatureFlags(0), heading=0.0)
    player = PlayerState(index=0, pos=Vec2())
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    world = world_with_creature(creature, rng=rng, perks=PerkCounts(), players=[player])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 10.0, 1, Vec2(), OwnerRef.from_creature(38))

    assert killed is False
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=1,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0]
    assert [record.caller for record in rng.records_since(before_calls)] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER,
    ]
    assert creature.heading == -0.10240000486373901


def test_damage_type1_heading_jitter_rounds_each_x87_operation() -> None:
    creature = CreatureState(
        active=True,
        hp=1.5709114074707031,
        size=45.0,
        flags=CreatureFlags(0),
        heading=-0.054194413125514984,
    )

    world = world_with_creature(creature, rng=ScriptedCrand(2932, fallback=ScriptedCrand.Fallback.REPEAT_LAST), perks=PerkCounts(), players=[PlayerState(index=0, pos=Vec2())])
    # Kill drops are out of scope; the guard skips their retry loop on the constant rolls.
    world.state.bonus_spawn_guard = True
    killed = creature_apply_damage(make_step_runtime(world, dt=0.09600000083446503), 0, 109.99357604980469, 1, Vec2(1.0, 1.0), OwnerRef.from_player(0))

    assert killed
    assert creature.heading == 0.03825003653764725


def test_damage_type1_heading_jitter_skips_ping_pong_creatures() -> None:
    creature = CreatureState(
        active=True,
        hp=100.0,
        size=50.0,
        flags=CreatureFlags.ANIM_PING_PONG,
        heading=0.0,
    )
    player = PlayerState(index=0, pos=Vec2())
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    world = world_with_creature(creature, rng=rng, perks=PerkCounts(), players=[player])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 10.0, 1, Vec2(), OwnerRef.from_creature(38))

    assert killed is False
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == []
    assert_float_close(creature.heading, 0.0)


def test_damage_type1_global_perks_apply_with_non_player_owner() -> None:
    creature = CreatureState(active=True, hp=74.0413, size=50.0, flags=CreatureFlags(0), heading=0.0)
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.URANIUM_FILLED_BULLETS] = 1
    perks[PerkId.BARREL_GREASER] = 1

    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST), perks=perks, players=[player])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 73.5593, 1, Vec2(), OwnerRef.from_creature(10))

    assert killed is True
    assert creature.hp == -131.92474365234375


def test_damage_modifier_chain_rounds_each_native_pc24_operation() -> None:
    creature = CreatureState(
        active=True,
        hp=435.9342956542969,
        size=50.0,
        flags=CreatureFlags.ANIM_PING_PONG,
    )
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.BARREL_GREASER] = 1
    perks[PerkId.DOCTOR] = 1

    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST), perks=perks, players=[player])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 261.8189392089844, CreatureDamageType.BULLET, Vec2(), OwnerRef.from_player(0))

    assert killed is True
    assert creature.hp == -3.921539306640625


def test_damage_float_parameter_rounds_at_the_native_abi_boundary() -> None:
    creature = CreatureState(active=True, hp=554.2709350585938, size=50.0)

    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST), perks=PerkCounts(), players=[PlayerState(index=0, pos=Vec2())])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 616.6504260335757, CreatureDamageType.EXPLOSION, Vec2(), OwnerRef.from_player(0))

    assert killed is True
    assert creature.hp == -62.3795166015625


def test_nonlethal_damage_does_not_reset_non_alive_lifecycle_stage() -> None:
    creature = CreatureState(active=True, hp=100.0, lifecycle_stage=12.0, size=50.0, flags=CreatureFlags(0))

    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST), perks=PerkCounts(), players=[PlayerState(index=0, pos=Vec2())])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 10.0, 3, Vec2(), OwnerRef.from_creature(0))

    assert killed is False
    assert_float_close(creature.lifecycle_stage, 12.0)


def test_lethal_shock_damage_spawns_armored_debris_after_death_handling() -> None:
    creature = CreatureState(
        active=True,
        hp=5.0,
        lifecycle_stage=16.0,
        size=50.0,
        flags=CreatureFlags.RANGED_ATTACK_SHOCK,
        pos=Vec2(10.0, 20.0),
        vel=Vec2(10.0, 20.0),
    )
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world = world_with_creature(creature, rng=rng)
    # Kill drops are out of scope here; the guard skips them before any draw.
    world.state.bonus_spawn_guard = True
    step_runtime = make_step_runtime(world, dt=0.016)
    before_calls = rng.calls

    killed = creature_apply_damage(step_runtime, 0, 10.0, CreatureDamageType.EXPLOSION, Vec2(1.0, 2.0), OwnerRef.from_creature(0))

    assert killed is True
    assert len(step_runtime.deaths) == 1
    # The hit's impulse, then the doubled impulse after `creature_handle_death`.
    assert creature.vel == Vec2(7.0, 14.0)
    active = world.state.effects.iter_active()
    assert len(active) == 5
    assert all(int(entry.effect_id) == int(EffectId.BURST) for entry in active)
    assert step_runtime.sfx == []
    assert [record.caller for record in rng.records_since(before_calls)][-20:] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_ROTATION,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_X,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_Y,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_SCALE_STEP,
    ] * 5


def test_split_children_inherit_only_initial_damage_impulse() -> None:
    creature = CreatureState(
        active=True,
        hp=5.0,
        max_hp=400.0,
        lifecycle_stage=16.0,
        size=40.0,
        flags=CreatureFlags.SPLIT_ON_DEATH,
        vel=Vec2(10.0, 20.0),
    )
    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    world.state.bonus_spawn_guard = True

    killed = creature_apply_damage(
        make_step_runtime(world, dt=0.016), 0, 10.0, CreatureDamageType.EXPLOSION, Vec2(1.0, 2.0), OwnerRef.from_player(0),
    )

    assert killed
    # The children split off inside `creature_handle_death`, before the doubled impulse.
    assert creature.vel == Vec2(7.0, 14.0)
    assert world.creatures.entries[1].vel == Vec2(9.0, 18.0)
    assert world.creatures.entries[2].vel == Vec2(9.0, 18.0)


def test_lethal_death_sfx_rand_draws_after_death_handling() -> None:
    creature = CreatureState(
        active=True,
        hp=5.0,
        lifecycle_stage=16.0,
        size=50.0,
        type_id=CreatureTypeId.TROOPER,
        flags=CreatureFlags(0),
        pos=Vec2(10.0, 20.0),
    )
    rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world = world_with_creature(creature, rng=rng)
    world.state.bonus_spawn_guard = True
    step_runtime = make_step_runtime(world, dt=0.016)
    before_calls = rng.calls

    killed = creature_apply_damage(step_runtime, 0, 10.0, CreatureDamageType.EXPLOSION, Vec2(), OwnerRef.from_creature(0))

    assert killed is True
    assert len(step_runtime.deaths) == 1
    assert [request.sfx_id for request in step_runtime.sfx] == [SfxId.TROOPER_DIE_02]
    assert rng.records_since(before_calls)[-1].caller == RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX


def test_resolve_native_death_sfx_default_fixes_trooper_uninitialized_fourth_slot() -> None:
    creature = CreatureState(type_id=CreatureTypeId.TROOPER, flags=CreatureFlags(0))
    rng = ScriptedCrand([0, 1, 2, 3])

    resolved = [resolve_native_death_sfx(creature, rng=rng, preserve_bugs=False) for _ in range(4)]

    assert resolved == [
        SfxId.TROOPER_DIE_01,
        SfxId.TROOPER_DIE_02,
        SfxId.TROOPER_DIE_03,
        SfxId.TROOPER_DIE_01,
    ]
    assert [record.caller for record in rng.records] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX,
    ] * 4


def test_resolve_native_death_sfx_preserve_bugs_keeps_trooper_pain_grunt_slot() -> None:
    creature = CreatureState(type_id=CreatureTypeId.TROOPER, flags=CreatureFlags(0))
    rng = ScriptedCrand(3, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    resolved = resolve_native_death_sfx(creature, rng=rng, preserve_bugs=True)

    assert resolved == SfxId.TROOPER_INPAIN_01
    assert [record.caller for record in rng.records] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX,
    ]


def test_lethal_branch_gates_on_entry_health_not_lifecycle() -> None:
    # Native creature_apply_damage runs the lethal branch whenever entry hp > 0,
    # even for a creature whose death already started (Shrinkifier corpse with
    # hp still positive); the Zig port mirrors this in applyDamage and
    # applyExplosionDamage.
    creature = CreatureState(active=True, hp=5.0, max_hp=400.0, lifecycle_stage=15.0, size=40.0)
    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    world.state.bonus_spawn_guard = True
    step_runtime = make_step_runtime(world, dt=0.016)

    killed = creature_apply_damage(
        step_runtime, 0, 10.0, CreatureDamageType.EXPLOSION, Vec2(), OwnerRef.from_local_player(0),
    )

    assert killed is True
    assert len(step_runtime.deaths) == 1
