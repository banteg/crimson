from __future__ import annotations

from typing import cast

import pytest

import crimson.sim.world_state as world_state_mod
from crimson.creatures.damage_types import CreatureDamageType
from crimson.creatures.runtime import CreatureDeath, CreatureUpdateResult
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import PrimaryStepCtx, SecondarySpawnSpec
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand, assert_rng_progression


def test_projectile_kill_awards_xp_same_step() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.hp = 1.0
    creature.max_hp = 1.0
    creature.reward_value = 10.0

    world.state.projectiles.spawn(
        pos=Vec2(float(creature.pos.x), float(creature.pos.y)),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_player(0),
    )

    assert player.experience == 0
    events = world.step(
        0.016,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    assert player.experience == 10
    assert len(events.deaths) == 1
    assert isinstance(events.deaths[0], CreatureDeath)
    assert events.deaths[0].xp_awarded == 10


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_sfx"),
    (
        (False, SfxId.TROOPER_DIE_01),
        (True, SfxId.TROOPER_INPAIN_01),
    ),
)
def test_world_step_trooper_death_sfx_respects_preserve_bugs(
    mocker,
    preserve_bugs: bool,
    expected_sfx: SfxId,
) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
        preserve_bugs=preserve_bugs,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.TROOPER
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags(0)
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.size = 50.0
    creature.reward_value = 0.0
    creature.lifecycle_stage = 16.0

    rng = ScriptedCrand(3, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    before_calls = rng.calls
    before_state = rng.state

    def _fake_projectile_step(*_args: object, **_kwargs: object) -> list[ProjectileHit]:
        ctx = cast("PrimaryStepCtx", _args[0])
        creature_damage_runtime = ctx.options.creature_damage_runtime
        assert creature_damage_runtime is not None
        creature_damage_runtime.apply_creature_damage(
            0,
            1000.0,
            CreatureDamageType.BULLET,
            Vec2(),
            OwnerRef.from_player(0),
        )
        return []

    mocker.patch.object(world.state.projectiles, "step", side_effect=_fake_projectile_step)
    events = world.step(
        0.1,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert events.sfx == [expected_sfx]
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=2,
        expected_after_state=3,
    )


def test_world_step_invalid_creature_type_id_fails_fast() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = cast("CreatureTypeId", 999)
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags(0)
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.size = 50.0
    creature.reward_value = 0.0
    creature.lifecycle_stage = 16.0

    with pytest.raises(KeyError):
        world.step(
            0.016,
            inputs=None,
            world_size=world_size,
            damage_scale_by_type={},
            detail_preset=5,
            fx_queue=FxQueue(),
            fx_queue_rotated=FxQueueRotated(),
            game_mode=GameMode.SURVIVAL,
            perk_progression_enabled=False,
        )


def test_detonation_followup_does_not_duplicate_resolved_death_sfx() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.ALIEN
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags(0)
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.size = 50.0
    creature.reward_value = 0.0
    creature.lifecycle_stage = 16.0

    world.state.secondary_projectiles.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(float(creature.pos.x), float(creature.pos.y)),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.DETONATION,
            time_to_live=1.0,
            owner=OwnerRef.from_player(0),
        ),
    )

    events = world.step(
        0.1,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    # Native detonation follow-up re-enters creature death handling for side effects,
    # but does not perform a second death-SFX random pick.
    assert len(events.deaths) == 2
    assert sum(
        key in {SfxId.ALIEN_DIE_01, SfxId.ALIEN_DIE_02, SfxId.ALIEN_DIE_03, SfxId.ALIEN_DIE_04}
        for key in events.sfx
    ) == 1


def test_projectile_lethal_hit_records_death_before_particles_update(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.ALIEN
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags(0)
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.size = 50.0
    creature.reward_value = 0.0
    creature.lifecycle_stage = 16.0

    record_death = mocker.patch.object(
        world_state_mod.WorldState,
        "_record_creature_death",
        wraps=world_state_mod.WorldState._record_creature_death,
        autospec=True,
    )

    def _fake_projectile_step(*_args: object, **_kwargs: object) -> list[ProjectileHit]:
        ctx = cast("PrimaryStepCtx", _args[0])
        creature_damage_runtime = ctx.options.creature_damage_runtime
        assert creature_damage_runtime is not None
        creature_damage_runtime.apply_creature_damage(
            0,
            1000.0,
            CreatureDamageType.BULLET,
            Vec2(),
            OwnerRef.from_player(0),
        )
        return []

    def _fake_particles_update(*_args: object, **_kwargs: object) -> None:
        assert record_death.call_count == 1

    mocker.patch.object(world.state.projectiles, "step", side_effect=_fake_projectile_step)
    mocker.patch.object(world.state.particles, "update", side_effect=_fake_particles_update)
    events = world.step(
        0.1,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert record_death.call_count == 1
    assert any(
        key in {SfxId.ALIEN_DIE_01, SfxId.ALIEN_DIE_02, SfxId.ALIEN_DIE_03, SfxId.ALIEN_DIE_04}
        for key in events.sfx
    )


def test_plague_kill_death_event_has_no_resolved_death_sfx(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    death = CreatureDeath(
        index=0,
        pos=Vec2(256.0, 256.0),
        type_id=CreatureTypeId.ALIEN,
        reward_value=0.0,
        xp_awarded=0,
        owner=OwnerRef.from_player(0),
    )

    def _fake_update(*args: object, **kwargs: object) -> CreatureUpdateResult:
        _ = args, kwargs
        return CreatureUpdateResult(deaths=(death,), sfx=(SfxId.UI_PANELCLICK,))

    mocker.patch.object(world.creatures, "update", side_effect=_fake_update)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    before_calls = rng.calls
    before_state = rng.state
    events = world.step(
        0.016,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert len(events.deaths) == 1
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == []
    assert events.sfx == [SfxId.UI_PANELCLICK]


def test_ranged_shock_lethal_has_no_resolved_death_sfx(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.ALIEN
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.lifecycle_stage = 16.0
    creature.reward_value = 0.0

    def _fake_projectile_step(*args: object, **kwargs: object) -> list[ProjectileHit]:
        _ = kwargs
        ctx = cast("PrimaryStepCtx", args[0])
        creature_damage_runtime = ctx.options.creature_damage_runtime
        if creature_damage_runtime is not None:
            creature_damage_runtime.apply_creature_damage(
                0,
                1000.0,
                CreatureDamageType.BULLET,
                Vec2(),
                OwnerRef.from_player(0),
            )
        return []

    mocker.patch.object(world.state.projectiles, "step", side_effect=_fake_projectile_step)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    before_calls = rng.calls
    before_state = rng.state
    events = world.step(
        0.016,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert len(events.deaths) == 1
    assert all(
        key not in {SfxId.ALIEN_DIE_01, SfxId.ALIEN_DIE_02, SfxId.ALIEN_DIE_03, SfxId.ALIEN_DIE_04}
        for key in events.sfx
    )
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=21,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 21


def test_world_step_uses_resolved_death_sfx_without_extra_rng(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    deaths = tuple(
        CreatureDeath(
            index=idx,
            pos=Vec2(200.0 + float(idx), 200.0),
            type_id=CreatureTypeId.ALIEN,
            reward_value=0.0,
            xp_awarded=0,
            owner=OwnerRef.from_player(0),
        )
        for idx in range(7)
    )
    death_sfx = (
        SfxId.ALIEN_DIE_01,
        SfxId.ALIEN_DIE_02,
        SfxId.ALIEN_DIE_03,
        SfxId.ALIEN_DIE_04,
        SfxId.ZOMBIE_DIE_01,
        SfxId.ZOMBIE_DIE_02,
        SfxId.ZOMBIE_DIE_03,
    )

    def _fake_update(*args: object, **kwargs: object) -> CreatureUpdateResult:
        _ = args, kwargs
        return CreatureUpdateResult(deaths=deaths, sfx=death_sfx)

    mocker.patch.object(world.creatures, "update", side_effect=_fake_update)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    before_calls = rng.calls
    before_state = rng.state
    events = world.step(
        0.016,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert len(events.deaths) == 7
    assert events.sfx[:7] == list(death_sfx)
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == []


def test_freeze_hit_path_triggers_tune_and_skips_hit_sfx(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    world.state.bonuses.freeze = 1.0

    plan_hit_sfx = mocker.patch.object(
        world_state_mod,
        "plan_hit_sfx",
        wraps=world_state_mod.plan_hit_sfx,
    )

    def _fake_projectile_step(*args: object, **_kwargs: object) -> list[ProjectileHit]:
        ctx = cast("PrimaryStepCtx", args[0])
        hit_runtime = ctx.options.hit_runtime
        hit = ProjectileHit(
            type_id=ProjectileTemplateId.PISTOL,
            origin=Vec2(0.0, 0.0),
            hit=Vec2(1.0, 1.0),
            target=Vec2(1.0, 1.0),
        )
        post_ctx = hit_runtime.begin_hit_presentation(hit)
        assert post_ctx is not None
        hit_runtime.finish_hit_presentation(hit, post_ctx)
        return [hit]

    mocker.patch.object(world.state.projectiles, "step", side_effect=_fake_projectile_step)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    before_calls = rng.calls
    before_state = rng.state
    events = world.step(
        0.016,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert plan_hit_sfx.call_count == 1
    # Freeze-active hits draw the post-hit burn rand, then the default freeze
    # shard angle plus the shard spawn draws (native order: burn before shard).
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=9,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 9
    assert events.hit_sfx == []
    assert events.trigger_game_tune is True


def test_perk_effects_step_uses_previous_aim_before_player_update() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    player.aim = Vec2(128.0, 256.0)
    world.players.append(player)

    seen: dict[str, Vec2] = {}
    original_perk_update = world_state_mod.perks_update_effects

    def _fake_perk_update(
        state: object,
        players: list[PlayerState],
        dt: float,
        *,
        creatures: object | None = None,
        fx_queue: object | None = None,
    ) -> None:
        _ = state, dt, creatures, fx_queue
        seen["aim"] = players[0].aim

    world_state_mod.perks_update_effects = _fake_perk_update  # type: ignore[assignment]
    try:
        world.step(
            0.016,
            inputs=[PlayerInput(aim=Vec2(900.0, 900.0))],
            world_size=world_size,
            damage_scale_by_type={},
            detail_preset=5,
            fx_queue=FxQueue(),
            fx_queue_rotated=FxQueueRotated(),
            game_mode=GameMode.SURVIVAL,
            perk_progression_enabled=False,
        )
    finally:
        world_state_mod.perks_update_effects = original_perk_update

    assert seen["aim"] == Vec2(128.0, 256.0)
    assert player.aim == Vec2(900.0, 900.0)


def test_first_secondary_rocket_hit_triggers_game_tune() -> None:
    from crimson.projectiles.runtime import SecondarySpawnSpec
    from crimson.projectiles.types import SecondaryProjectileTypeId

    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0
    creature.size = 50.0

    world.state.secondary_projectiles.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(100.0, 100.0),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.ROCKET,
            owner=OwnerRef.from_player(0),
        ),
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    # Native secondary-rocket hits run the same first-hit game-tune branch as
    # bullet hits instead of the panned explosion sound.
    assert events.trigger_game_tune is True
    assert SfxId.EXPLOSION_MEDIUM not in world.state.sfx_queue
    assert SfxId.EXPLOSION_MEDIUM not in events.hit_sfx
