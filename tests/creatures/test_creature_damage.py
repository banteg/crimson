from __future__ import annotations

from collections.abc import Callable

from crimson.creatures.damage import (
    creature_apply_damage,
    creature_apply_damage_with_lethal_followup,
    resolve_native_death_sfx,
)
from crimson.creatures.damage_runtime import CreatureDamageRuntime
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects_atlas import EffectId
from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression


def test_damage_type1_heading_jitter_uses_rand_without_player_attacker() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0, flags=CreatureFlags(0), heading=0.0)
    player = PlayerState(index=0, pos=Vec2())
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_creature(38),
        dt=0.016,
        players=[player],
        rng=rng,
    )

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
    # Native stores the jittered heading as f32.
    assert_float_close(creature.heading, float(f32(-0.1024)))


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

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_creature(38),
        dt=0.016,
        players=[player],
        rng=rng,
    )

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
    player.perk_counts[int(PerkId.URANIUM_FILLED_BULLETS)] = 1
    player.perk_counts[int(PerkId.BARREL_GREASER)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=73.5593,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_creature(10),
        dt=0.016,
        players=[player],
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is True
    assert_float_close(creature.hp, -131.92474)


def test_nonlethal_damage_does_not_reset_non_alive_hitbox_size() -> None:
    creature = CreatureState(active=True, hp=100.0, lifecycle_stage=12.0, size=50.0, flags=CreatureFlags(0))

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=3,
        impulse=Vec2(),
        owner=OwnerRef.from_creature(0),
        dt=0.016,
        players=[],
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is False
    assert_float_close(creature.lifecycle_stage, 12.0)


def test_lethal_shock_damage_spawns_armored_debris_after_death_handling() -> None:
    state = GameplayState()
    creature = CreatureState(
        active=True,
        hp=5.0,
        lifecycle_stage=16.0,
        size=50.0,
        flags=CreatureFlags.RANGED_ATTACK_SHOCK,
        pos=Vec2(10.0, 20.0),
    )
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    order: list[str] = []

    class _Runtime(CreatureDamageRuntime):
        def on_creature_lethal(
            self,
            creature_index: int,
            resolve_death_sfx: Callable[[], tuple[SfxId, ...]],
        ) -> None:
            # Native order: `creature_handle_death` draws happen here, before the
            # shock-burst / death-SFX rands.
            assert rng.calls - before_calls == 0
            order.append(f"handle_death:{creature_index}")
            assert resolve_death_sfx() == ()
            order.append("death_followup")

    killed = creature_apply_damage_with_lethal_followup(
        creature,
        creature_index=7,
        damage_amount=10.0,
        damage_type=3,
        impulse=Vec2(),
        owner=OwnerRef.from_creature(0),
        dt=0.016,
        players=[],
        rng=rng,
        effects=state.effects,
        detail_preset=5,
        creature_damage_runtime=_Runtime(),
    )

    assert killed is True
    assert order == ["handle_death:7", "death_followup"]
    active = state.effects.iter_active()
    assert len(active) == 5
    assert all(int(entry.effect_id) == int(EffectId.BURST) for entry in active)
    assert rng.calls - before_calls == 20
    assert [record.caller for record in rng.records_since(before_calls)] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_ROTATION,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_X,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_Y,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_SCALE_STEP,
    ] * 5


def test_lethal_death_sfx_rand_draws_after_death_handling() -> None:
    state = GameplayState()
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
    before_calls = rng.calls
    order: list[str] = []

    class _Runtime(CreatureDamageRuntime):
        def on_creature_lethal(
            self,
            creature_index: int,
            resolve_death_sfx: Callable[[], tuple[SfxId, ...]],
        ) -> None:
            assert rng.calls - before_calls == 0
            order.append("handle_death")
            assert resolve_death_sfx() == (SfxId.TROOPER_DIE_02,)
            order.append("death_followup")

    killed = creature_apply_damage_with_lethal_followup(
        creature,
        creature_index=0,
        damage_amount=10.0,
        damage_type=3,
        impulse=Vec2(),
        owner=OwnerRef.from_creature(0),
        dt=0.016,
        players=[],
        rng=rng,
        effects=state.effects,
        detail_preset=5,
        creature_damage_runtime=_Runtime(),
    )

    assert killed is True
    assert order == ["handle_death", "death_followup"]
    assert rng.calls - before_calls == 1
    assert [record.caller for record in rng.records_since(before_calls)] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX,
    ]


def test_resolve_native_death_sfx_default_fixes_trooper_uninitialized_fourth_slot() -> None:
    creature = CreatureState(type_id=CreatureTypeId.TROOPER, flags=CreatureFlags(0))
    rng = ScriptedCrand([0, 1, 2, 3])

    resolved = [resolve_native_death_sfx(creature, rng=rng, preserve_bugs=False)[0] for _ in range(4)]

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

    assert resolved == (SfxId.TROOPER_INPAIN_01,)
    assert [record.caller for record in rng.records] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX,
    ]
