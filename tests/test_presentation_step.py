from __future__ import annotations

from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.gameplay import BonusPickupEvent, GameplayState, PlayerState
from crimson.projectiles import ProjectileHit, ProjectileTypeId
from crimson.sim.presentation_step import (
    apply_world_presentation_step,
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


def test_plan_hit_sfx_skips_first_hit_when_tune_not_started() -> None:
    trigger_game_tune, keys = plan_hit_sfx_keys(
        _hits(2),
        game_mode=int(GameMode.SURVIVAL),
        demo_mode_active=False,
        game_tune_started=False,
        rand=lambda: 0,
    )

    assert trigger_game_tune is True
    assert keys == ["sfx_bullet_hit_01"]


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
