from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.presentation_step import (
    plan_hit_sfx,
    plan_world_presentation_step,
    queue_projectile_decals,
)
from crimson.sim.state_types import BonusPickupEvent, PlayerState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand, assert_float_close, assert_rng_progression


def _hits(count: int, *, type_id: ProjectileTemplateId = ProjectileTemplateId.PISTOL) -> list[ProjectileHit]:
    hits: list[ProjectileHit] = []
    for _ in range(int(count)):
        hits.append(
            ProjectileHit(
                type_id=type_id,
                origin=Vec2(0.0, 0.0),
                hit=Vec2(1.0, 1.0),
                target=Vec2(1.0, 1.0),
            ),
        )
    return hits


def test_plan_hit_sfx_skips_first_hit_when_tune_not_started() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    trigger_game_tune, keys = plan_hit_sfx(
        _hits(2),
        game_mode=GameMode.SURVIVAL,
        demo_mode_active=False,
        game_tune_started=False,
        rng=rng,
    )

    assert trigger_game_tune is True
    assert keys == [SfxId.BULLET_HIT_01]
    assert rng.calls == 2
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


def test_plan_hit_sfx_no_skip_when_tune_started() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    trigger_game_tune, keys = plan_hit_sfx(
        _hits(2),
        game_mode=GameMode.SURVIVAL,
        demo_mode_active=False,
        game_tune_started=True,
        rng=rng,
    )

    assert trigger_game_tune is False
    assert keys == [SfxId.BULLET_HIT_01, SfxId.BULLET_HIT_01]
    assert rng.calls == 2
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


def test_plan_world_presentation_step_orders_sfx() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.weapon.weapon_id = WeaponId.PISTOL
    player.shot_seq = 1

    state.perk_selection.pending_count = 1

    commands = plan_world_presentation_step(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hits=[],
        pickups=[
            BonusPickupEvent(
                player_index=0,
                bonus_id=BonusId.POINTS,
                amount=100,
                pos=Vec2(),
            ),
        ],
        event_sfx=[
            SfxId.UI_PANELCLICK,
            SfxId.UI_BUTTONCLICK,
            SfxId.UI_CLINK_01,
            SfxId.SHOCK_HIT_01,
            SfxId.EXPLOSION_SMALL,
        ],
        prev_audio=[(0, False, 0.0)],
        prev_perk_pending=0,
        game_mode=GameMode.SURVIVAL,
        demo_mode_active=False,
        perk_progression_enabled=True,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=False,
    )

    assert commands.trigger_game_tune is False
    assert commands.sfx == (
        SfxId.UI_LEVELUP,
        SfxId.PISTOL_FIRE,
        SfxId.UI_BONUS,
        SfxId.UI_PANELCLICK,
        SfxId.UI_BUTTONCLICK,
        SfxId.UI_CLINK_01,
        SfxId.SHOCK_HIT_01,
    )


def test_queue_projectile_decals_consumes_rand() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=74,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 74
    assert fx_queue.count > 0


def test_queue_projectile_decals_native_default_draw_count() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    # Native `projectile_update` default creature-hit path consumes:
    # - 2x blood splatter calls + 2 branch rolls,
    # - 1 extra throwaway rand,
    # - 3x decal spread rolls + 12x `fx_queue_add_random` draws.
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=74,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 74
    assert [
        record.caller
        for record in rng.records_since(before_calls)
        if record.caller
        in {
            RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN,
            RngCallerStatic.PROJECTILE_UPDATE_DECAL_SPREAD,
        }
    ] == [
        RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN,
        RngCallerStatic.PROJECTILE_UPDATE_DECAL_SPREAD,
        RngCallerStatic.PROJECTILE_UPDATE_DECAL_SPREAD,
        RngCallerStatic.PROJECTILE_UPDATE_DECAL_SPREAD,
    ]
    assert fx_queue.count == 12


def test_queue_projectile_decals_blade_gun_spawns_native_pre_branch_splatter(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    splatter_angles: list[float] = []

    def _record_blood_splatter(
        *,
        pos: Vec2,
        angle: float,
        age: float,
        rng,
        detail_preset: int,
        violence_disabled: int,
    ) -> None:
        _ = pos, age, rng, detail_preset, violence_disabled
        splatter_angles.append(float(angle))

    mocker.patch.object(
        state.effects,
        "spawn_blood_splatter",
        side_effect=_record_blood_splatter,
    )
    rng = ScriptedCrand(list(range(256)), fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=ProjectileTemplateId.BLADE_GUN),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert len(splatter_angles) >= 8
    for idx in range(8):
        assert_float_close(splatter_angles[idx], float(idx) * 0.024543693)
    assert [
        record.caller
        for record in rng.records_since()
        if record.caller == RngCallerStatic.PROJECTILE_UPDATE_BLADE_GUN_SPLATTER_ANGLE
    ] == [RngCallerStatic.PROJECTILE_UPDATE_BLADE_GUN_SPLATTER_ANGLE] * 8


def test_queue_projectile_decals_bloody_mess_tags_exact_pre_hit_callers() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert [
        record.caller
        for record in rng.records_since()
        if record.caller
        in {
            RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_SPREAD,
            RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_1,
            RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DY_1,
            RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_2,
            RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DY_2,
        }
    ] == [RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_SPREAD] * 8 + [
        RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_1,
        RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DY_1,
        RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DX_2,
        RngCallerStatic.PROJECTILE_UPDATE_BLOODY_MESS_DECAL_DY_2,
    ] * 3


def test_queue_projectile_decals_default_tags_exact_reverse_splatter_gate() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert [
        record.caller
        for record in rng.records_since()
        if record.caller == RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_REVERSE_SPLATTER_GATE
    ] == [
        RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_REVERSE_SPLATTER_GATE,
        RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_REVERSE_SPLATTER_GATE,
    ]


def test_queue_projectile_decals_fire_bullets_freeze_runs_six_shard_iterations(mocker) -> None:
    state = GameplayState()
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    spawn_freeze_shard = mocker.patch.object(
        state.effects,
        "spawn_freeze_shard",
        wraps=state.effects.spawn_freeze_shard,
    )
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=ProjectileTemplateId.FIRE_BULLETS),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert spawn_freeze_shard.call_count == 6
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=79,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 79
    assert fx_queue.count == 6


def test_queue_projectile_decals_fire_bullets_freeze_tags_exact_streak_callers(mocker) -> None:
    state = GameplayState()
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    spawn_freeze_shard = mocker.patch.object(
        state.effects,
        "spawn_freeze_shard",
        wraps=state.effects.spawn_freeze_shard,
    )
    per_loop = [50, 70, 0, 0, 0] + [0] * 10
    rng = ScriptedCrand([0] + per_loop * 6, fallback=ScriptedCrand.Fallback.RAISE)

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=ProjectileTemplateId.FIRE_BULLETS),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert spawn_freeze_shard.call_count == 6
    streak_callers = [
        record.caller
        for record in rng.records_since()
        if record.caller
        in {
            RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST_GT4,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST_GT7,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_BURN,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_FREEZE_ANGLE,
        }
    ]
    assert (
        streak_callers
        == [RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN]
        + [
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST_GT4,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST_GT7,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_BURN,
            RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_FREEZE_ANGLE,
        ]
        * 6
    )


def test_queue_projectile_decals_fire_bullets_freeze_runs_hooks_with_violence_disabled_set(mocker) -> None:
    state = GameplayState()
    state.bonuses.freeze = 1.0
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    spawn_freeze_shard = mocker.patch.object(
        state.effects,
        "spawn_freeze_shard",
        wraps=state.effects.spawn_freeze_shard,
    )
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1, type_id=ProjectileTemplateId.FIRE_BULLETS),
        rng=rng,
        detail_preset=5,
        violence_disabled=1,
    )

    assert spawn_freeze_shard.call_count == 6
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=79,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 79
    assert fx_queue.count == 6


def test_queue_projectile_decals_orders_blood_before_decals() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    queue_projectile_decals(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hits=_hits(1),
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=74,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == [0] * 74
    assert fx_queue.count == 12


def test_plan_world_presentation_step_prefers_preplanned_hit_outputs() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    before_calls = rng.calls
    before_state = rng.state

    commands = plan_world_presentation_step(
        state=state,
        players=[player],
        fx_queue=FxQueue(),
        hits=_hits(1),
        pickups=[],
        event_sfx=[],
        prev_audio=[(0, False, 0.0)],
        prev_perk_pending=0,
        game_mode=GameMode.SURVIVAL,
        demo_mode_active=False,
        perk_progression_enabled=True,
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=False,
        trigger_game_tune=True,
        hit_sfx=[SfxId.BULLET_HIT_01],
    )

    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
    )
    assert rng.values_since(before_calls) == []
    assert commands.trigger_game_tune is True
    assert commands.sfx == (SfxId.BULLET_HIT_01,)
