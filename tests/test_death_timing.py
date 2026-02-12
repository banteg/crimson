from __future__ import annotations

from grim.geom import Vec2

from crimson.creatures.runtime import CreatureDeath
from crimson.creatures.runtime import CreatureUpdateResult
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput, PlayerState
from crimson.projectiles import ProjectileHit, ProjectileTypeId, SecondaryProjectileTypeId
import crimson.sim.world_state as world_state_mod
from crimson.sim.world_state import WorldState


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


def test_detonation_followup_does_not_double_plan_death_sfx() -> None:
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

    calls: list[list[int | None]] = []
    original = world_state_mod.plan_death_sfx_keys

    def _fake_plan(deaths: tuple[object, ...] | list[object], *, rand: object) -> list[str]:
        calls.append([getattr(death, "index", None) for death in deaths])
        return ["death"] if deaths else []

    world_state_mod.plan_death_sfx_keys = _fake_plan
    try:
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
    finally:
        world_state_mod.plan_death_sfx_keys = original

    # Native detonation follow-up re-enters creature death handling for side effects,
    # but does not perform a second death-SFX random pick.
    assert len(events.deaths) == 2
    assert calls == [[0]]
    assert events.sfx == ["death"]


def test_death_sfx_rand_consumes_past_cap() -> None:
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

    calls = {"count": 0}
    original_plan = world_state_mod.plan_death_sfx_keys
    original_update = world.creatures.update

    def _fake_plan(deaths_now: tuple[object, ...] | list[object], *, rand: object) -> list[str]:
        calls["count"] += 1
        if callable(rand):
            rand()
        return ["death"] if deaths_now else []

    def _fake_update(*args: object, **kwargs: object) -> CreatureUpdateResult:
        _ = args, kwargs
        return CreatureUpdateResult(deaths=deaths, sfx=())

    world_state_mod.plan_death_sfx_keys = _fake_plan
    world.creatures.update = _fake_update  # type: ignore[assignment]
    try:
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
    finally:
        world_state_mod.plan_death_sfx_keys = original_plan
        world.creatures.update = original_update  # type: ignore[assignment]

    assert len(events.deaths) == 7
    assert len(events.sfx) == 5
    assert calls["count"] == 7


def test_freeze_hit_path_still_plans_hit_sfx() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    world.state.bonuses.freeze = 1.0

    calls = {"count": 0}
    original_plan = world_state_mod.plan_hit_sfx_keys
    original_update = world.state.projectiles.update

    def _fake_plan(
        hits: list[ProjectileHit],
        *,
        game_mode: int,
        demo_mode_active: bool,
        game_tune_started: bool,
        rand: object,
        beam_types: frozenset[int] = frozenset(),
    ) -> tuple[bool, list[str]]:
        _ = hits, game_mode, demo_mode_active, game_tune_started, rand, beam_types
        calls["count"] += 1
        return True, ["sfx_bullet_hit_01"]

    def _fake_projectile_update(*args: object, **kwargs: object) -> list[ProjectileHit]:
        _ = args
        on_hit = kwargs["on_hit"]
        on_hit_post = kwargs["on_hit_post"]
        hit = ProjectileHit(
            type_id=int(ProjectileTypeId.PISTOL),
            origin=Vec2(0.0, 0.0),
            hit=Vec2(1.0, 1.0),
            target=Vec2(1.0, 1.0),
        )
        post_ctx = on_hit(hit)
        on_hit_post(hit, post_ctx)
        return [hit]

    world_state_mod.plan_hit_sfx_keys = _fake_plan
    world.state.projectiles.update = _fake_projectile_update  # type: ignore[assignment]
    try:
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
    finally:
        world_state_mod.plan_hit_sfx_keys = original_plan
        world.state.projectiles.update = original_update  # type: ignore[assignment]

    assert calls["count"] == 1
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
        world_state_mod.perks_update_effects = original_perk_update  # type: ignore[assignment]

    assert seen["aim"] == Vec2(128.0, 256.0)
    assert player.aim == Vec2(900.0, 900.0)
