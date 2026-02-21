from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import cast

import crimson.sim.world_state as world_state_mod
from crimson.creatures.runtime import CreatureDeath, CreatureUpdateResult
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.projectiles import ProjectileHit, ProjectileTypeId, ProjectileUpdateOptions, SecondaryProjectileTypeId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_rng_progression


def test_projectile_kill_awards_xp_same_step() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
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
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-1,
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
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )
    assert player.experience == 10
    assert len(events.deaths) == 1
    assert isinstance(events.deaths[0], CreatureDeath)
    assert events.deaths[0].xp_awarded == 10


def test_detonation_followup_does_not_double_plan_death_sfx(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = 2
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags(0)
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.size = 50.0
    creature.reward_value = 0.0
    creature.hitbox_size = 16.0

    world.state.secondary_projectiles.spawn(
        pos=Vec2(float(creature.pos.x), float(creature.pos.y)),
        angle=0.0,
        type_id=int(SecondaryProjectileTypeId.DETONATION),
        time_to_live=1.0,
        owner_id=-1,
    )

    def _fake_plan(
        deaths: Sequence[CreatureDeath] | tuple[object, ...],
        *,
        rand: Callable[[], int],
    ) -> list[str]:
        _ = rand
        return ["death"] if deaths else []
    plan_death_sfx = mocker.patch.object(world_state_mod, "plan_death_sfx_keys", side_effect=_fake_plan)
    events = world.step(
        0.1,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    # Native detonation follow-up re-enters creature death handling for side effects,
    # but does not perform a second death-SFX random pick.
    assert len(events.deaths) == 2
    plan_death_sfx.assert_called_once()
    called_deaths = cast("Sequence[CreatureDeath]", plan_death_sfx.call_args.args[0])
    assert [death.index for death in called_deaths] == [0]
    assert events.sfx == ["death"]


def test_plague_kill_death_event_skips_world_death_sfx_planning(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    death = CreatureDeath(
        index=0,
        pos=Vec2(256.0, 256.0),
        type_id=2,
        reward_value=0.0,
        xp_awarded=0,
        owner_id=-1,
        plan_death_sfx=False,
    )

    plan_death_sfx = mocker.patch.object(
        world_state_mod,
        "plan_death_sfx_keys",
        wraps=world_state_mod.plan_death_sfx_keys,
    )

    def _fake_update(*args: object, **kwargs: object) -> CreatureUpdateResult:
        _ = args, kwargs
        return CreatureUpdateResult(deaths=(death,), sfx=("plague_contact",))

    mocker.patch.object(world.creatures, "update", side_effect=_fake_update)
    rng = MockCrand(0, fallback="repeat_last")
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
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert len(events.deaths) == 1
    assert plan_death_sfx.call_count == 0
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
        expected_hash="da39a3ee5e6b4b0d",
    )
    assert events.sfx == ["plague_contact"]


def test_ranged_shock_lethal_skips_world_death_sfx_planning(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = 2
    creature.pos = Vec2(256.0, 256.0)
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.hp = 25.0
    creature.max_hp = 25.0
    creature.hitbox_size = 16.0
    creature.reward_value = 0.0

    plan_death_sfx = mocker.patch.object(
        world_state_mod,
        "plan_death_sfx_keys",
        wraps=world_state_mod.plan_death_sfx_keys,
    )

    def _fake_projectile_update(*args: object, **kwargs: object) -> list[ProjectileHit]:
        _ = args
        options = cast("ProjectileUpdateOptions", kwargs.get("options"))
        apply_creature_damage = options.apply_creature_damage if options is not None else None
        if apply_creature_damage is not None:
            apply_creature_damage(0, 1000.0, int(ProjectileTypeId.PISTOL), Vec2(), -1)
        return []

    mocker.patch.object(world.state.projectiles, "update", side_effect=_fake_projectile_update)
    rng = MockCrand(0, fallback="repeat_last")
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
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert len(events.deaths) == 1
    assert events.deaths[0].plan_death_sfx is False
    assert plan_death_sfx.call_count == 0
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=41,
        expected_after_state=0,
        expected_hash="3ba5b0d89c1cec5a",
    )


def test_death_sfx_rand_consumes_past_cap(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))

    deaths = tuple(
        CreatureDeath(
            index=idx,
            pos=Vec2(200.0 + float(idx), 200.0),
            type_id=2,
            reward_value=0.0,
            xp_awarded=0,
            owner_id=-1,
        )
        for idx in range(7)
    )

    def _fake_update(*args: object, **kwargs: object) -> CreatureUpdateResult:
        _ = args, kwargs
        return CreatureUpdateResult(deaths=deaths, sfx=())

    mocker.patch.object(world.creatures, "update", side_effect=_fake_update)
    rng = MockCrand(0, fallback="repeat_last")
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
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert len(events.deaths) == 7
    assert len(events.sfx) == 5
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=7,
        expected_after_state=0,
        expected_hash="06cb3d45c9fff74c",
    )


def test_freeze_hit_path_still_plans_hit_sfx(mocker) -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    world.state.bonuses.freeze = 1.0

    plan_hit_sfx = mocker.patch.object(
        world_state_mod,
        "plan_hit_sfx_keys",
        wraps=world_state_mod.plan_hit_sfx_keys,
    )

    def _fake_projectile_update(
        *_args: object,
        options: ProjectileUpdateOptions,
        **_kwargs: object,
    ) -> list[ProjectileHit]:
        on_hit = options.on_hit
        on_hit_post = options.on_hit_post
        if on_hit is None or on_hit_post is None:
            return []
        hit = ProjectileHit(
            type_id=int(ProjectileTypeId.PISTOL),
            origin=Vec2(0.0, 0.0),
            hit=Vec2(1.0, 1.0),
            target=Vec2(1.0, 1.0),
        )
        post_ctx = on_hit(hit)
        on_hit_post(hit, post_ctx)
        return [hit]

    mocker.patch.object(world.state.projectiles, "update", side_effect=_fake_projectile_update)
    rng = MockCrand(0, fallback="repeat_last")
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
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert plan_hit_sfx.call_count == 1
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=2,
        expected_after_state=0,
        expected_hash="e499ce7a21cd46c8",
    )
    assert events.hit_sfx == ["sfx_bullet_hit_01"]
    assert events.trigger_game_tune is True


def test_perk_effects_step_uses_previous_aim_before_player_update() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
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
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=False,
        )
    finally:
        world_state_mod.perks_update_effects = original_perk_update

    assert seen["aim"] == Vec2(128.0, 256.0)
    assert player.aim == Vec2(900.0, 900.0)
