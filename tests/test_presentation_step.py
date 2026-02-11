from __future__ import annotations

from types import SimpleNamespace

from crimson.creatures.spawn import CreatureTypeId
from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.gameplay import BonusPickupEvent, GameplayState, PlayerState
from crimson.projectiles import ProjectileHit, ProjectileTypeId
from crimson.sim.presentation_step import (
    apply_world_presentation_step,
    plan_death_sfx_keys,
    plan_hit_sfx_keys,
    queue_projectile_decals,
)
from grim.geom import Vec2


def _hits(count: int, *, type_id: int = int(ProjectileTypeId.PISTOL)) -> list[ProjectileHit]:
    hits: list[ProjectileHit] = []
    for _ in range(int(count)):
        hits.append(
            ProjectileHit(
                type_id=int(type_id),
                origin=Vec2(0.0, 0.0),
                hit=Vec2(1.0, 1.0),
                target=Vec2(1.0, 1.0),
            )
        )
    return hits


def test_plan_hit_sfx_includes_first_hit_when_tune_not_started() -> None:
    trigger_game_tune, keys = plan_hit_sfx_keys(
        _hits(2),
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        game_tune_started=False,
        rand=lambda: 0,
    )

    assert trigger_game_tune is True
    assert keys == ["sfx_bullet_hit_01", "sfx_bullet_hit_01"]


def test_plan_hit_sfx_no_skip_when_tune_started() -> None:
    trigger_game_tune, keys = plan_hit_sfx_keys(
        _hits(2),
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        game_tune_started=True,
        rand=lambda: 0,
    )

    assert trigger_game_tune is False
    assert keys == ["sfx_bullet_hit_01", "sfx_bullet_hit_01"]


def test_plan_death_sfx_allows_five_randomized_deaths() -> None:
    draws = {"count": 0}

    def rand() -> int:
        draws["count"] += 1
        return 0

    deaths = [SimpleNamespace(type_id=int(CreatureTypeId.ZOMBIE)) for _ in range(5)]
    keys = plan_death_sfx_keys(deaths, rand=rand)

    assert len(keys) == 5
    assert draws["count"] == 5


def test_apply_world_presentation_step_orders_sfx() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.weapon_id = int(ProjectileTypeId.PISTOL)
    player.shot_seq = 1

    state.perk_selection.pending_count = 1

    commands = apply_world_presentation_step(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hits=[],
        deaths=(),
        pickups=[
            BonusPickupEvent(
                player_index=0,
                bonus_id=1,
                amount=100,
                pos=Vec2(),
            )
        ],
        event_sfx=["sfx_custom_1", "sfx_custom_2", "sfx_custom_3", "sfx_custom_4", "sfx_custom_5"],
        prev_audio=[(0, False, 0.0)],
        prev_perk_pending=0,
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        perk_progression_enabled=True,
        rand=lambda: 0,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
    )

    assert commands.trigger_game_tune is False
    assert commands.sfx_keys == [
        "sfx_ui_levelup",
        "sfx_pistol_fire",
        "sfx_ui_bonus",
        "sfx_custom_1",
        "sfx_custom_2",
        "sfx_custom_3",
        "sfx_custom_4",
    ]


def test_queue_projectile_decals_consumes_rand() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()

    draws = {"count": 0}

    def rand() -> int:
        draws["count"] += 1
        return 0

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rand=rand,
        detail_preset=5,
        fx_toggle=0,
    )

    assert draws["count"] > 0
    assert fx_queue.count > 0


def test_queue_projectile_decals_native_default_draw_count() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()

    draws = {"count": 0}

    def rand() -> int:
        draws["count"] += 1
        return 0

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rand=rand,
        detail_preset=5,
        fx_toggle=0,
    )

    # Native `projectile_update` default creature-hit path consumes:
    # - 2x blood splatter calls + 2 branch rolls,
    # - 1 extra throwaway rand,
    # - 3x decal spread rolls + 12x `fx_queue_add_random` draws.
    assert draws["count"] == 74
    assert fx_queue.count == 12


def test_queue_projectile_decals_fire_bullets_freeze_runs_six_shard_iterations() -> None:
    state = GameplayState()
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    shard_calls = {"count": 0}

    orig_spawn_freeze_shard = state.effects.spawn_freeze_shard

    def _spawn_freeze_shard(**kwargs):  # noqa: ANN003
        shard_calls["count"] += 1
        return orig_spawn_freeze_shard(**kwargs)

    state.effects.spawn_freeze_shard = _spawn_freeze_shard  # type: ignore[method-assign]

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=int(ProjectileTypeId.FIRE_BULLETS)),
        rand=lambda: 0,
        detail_preset=5,
        fx_toggle=0,
    )

    assert shard_calls["count"] == 6
    assert fx_queue.count == 6


def test_queue_projectile_decals_orders_blood_before_decals() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    events: list[str] = []

    orig_spawn_blood = state.effects.spawn_blood_splatter
    orig_add_random = fx_queue.add_random

    def _spawn_blood_splatter(**kwargs):
        events.append("blood")
        return orig_spawn_blood(**kwargs)

    def _add_random(**kwargs):
        events.append("decal")
        return orig_add_random(**kwargs)

    state.effects.spawn_blood_splatter = _spawn_blood_splatter  # type: ignore[method-assign]
    fx_queue.add_random = _add_random  # type: ignore[method-assign]

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rand=lambda: 0,
        detail_preset=5,
        fx_toggle=0,
    )

    assert "blood" in events
    assert "decal" in events
    assert events.index("blood") < events.index("decal")


def test_apply_world_presentation_step_prefers_preplanned_hit_outputs() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    draws = {"count": 0}

    def rand() -> int:
        draws["count"] += 1
        return 0

    commands = apply_world_presentation_step(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hits=_hits(1),
        deaths=(),
        pickups=[],
        event_sfx=[],
        prev_audio=[(0, False, 0.0)],
        prev_perk_pending=0,
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        perk_progression_enabled=True,
        rand=rand,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
        trigger_game_tune=True,
        hit_sfx=["sfx_bullet_hit_01"],
    )

    assert draws["count"] == 0
    assert commands.trigger_game_tune is True
    assert commands.sfx_keys == ["sfx_bullet_hit_01"]
