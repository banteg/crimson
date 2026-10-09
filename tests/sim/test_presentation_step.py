from __future__ import annotations

from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.presentation_step import (
    plan_hit_sfx,
)
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.decals import queue_projectile_decals
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
        game_tune_started=False,
        rng=rng,
    )

    assert trigger_game_tune is True
    assert sfx_ids(keys) == [SfxId.BULLET_HIT_01]
    assert rng.calls == 2
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


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
