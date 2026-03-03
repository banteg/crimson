from __future__ import annotations

import math
from pathlib import Path

from crimson.projectiles.types import Projectile, ProjectileTemplateId, SecondaryProjectile, SecondaryProjectileTypeId
from crimson.sim.state_types import PlayerState
from crimson.views.lighting_debug import (
    EMISSIVE_PROFILES,
    EmissiveProfile,
    LightingDebugView,
    TransientLight,
    _auto_tune_selection_score,
    _AutoTunePreset,
    _AutoTuneResult,
    _build_static_occluders,
    _profile_light_defaults,
    _shadow_frame_metrics,
    _shadow_quality_score,
    collect_shadow_lights,
    collect_shadow_occluders,
    tick_transient_lights,
)
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from grim.view import ViewContext
from tests.factories import make_creature_state as _creature
from tests.helpers import assert_float_close


def _player(*, pos: Vec2, health: float = 100.0, size: float = 48.0) -> PlayerState:
    return PlayerState(index=0, pos=pos, health=float(health), size=float(size))


def _projectile(
    *,
    type_id: int,
    pos: Vec2,
    active: bool = True,
    angle: float = 0.0,
    origin: Vec2 | None = None,
) -> Projectile:
    return Projectile(
        active=bool(active),
        type_id=int(type_id),
        pos=pos,
        origin=pos if origin is None else origin,
        angle=float(angle),
    )


def _secondary(
    *,
    type_id: int,
    pos: Vec2,
    active: bool = True,
    angle: float = 0.0,
    vel: Vec2 | None = None,
    detonation_scale: float = 1.0,
) -> SecondaryProjectile:
    return SecondaryProjectile(
        active=bool(active),
        type_id=int(type_id),
        pos=pos,
        angle=float(angle),
        vel=Vec2() if vel is None else vel,
        detonation_scale=float(detonation_scale),
    )


def test_collect_shadow_occluders_filters_invalid_entities_and_clamps_count() -> None:
    player = _player(pos=Vec2(512.0, 512.0), health=100.0, size=48.0)
    creatures = [
        _creature(active=False, pos=Vec2(540.0, 512.0), hp=30.0, lifecycle_stage=16.0, size=40.0),
        _creature(active=True, pos=Vec2(560.0, 512.0), hp=30.0, lifecycle_stage=16.0, size=40.0),
        _creature(active=True, pos=Vec2(580.0, 512.0), hp=0.0, lifecycle_stage=16.0, size=40.0),
        _creature(active=True, pos=Vec2(float("nan"), 520.0), hp=30.0, lifecycle_stage=16.0, size=40.0),
        _creature(active=True, pos=Vec2(620.0, 512.0), hp=30.0, lifecycle_stage=0.0, size=40.0),
        _creature(active=True, pos=Vec2(640.0, 512.0), hp=30.0, lifecycle_stage=16.0, size=40.0),
    ]

    occluders = collect_shadow_occluders(player, creatures, max_occluders=2)

    assert len(occluders) == 2
    assert_float_close(occluders[0].pos.x, 512.0)
    assert_float_close(occluders[1].pos.x, 560.0)
    assert occluders[0].radius > 0.0
    assert occluders[1].radius > 0.0


def test_collect_shadow_lights_clamps_count_and_is_deterministic() -> None:
    transients = [
        TransientLight(pos=Vec2(100.0, 100.0), radius=40.0, strength=1.0, ttl=0.4, age=0.0),
        TransientLight(pos=Vec2(110.0, 100.0), radius=40.0, strength=0.8, ttl=0.4, age=0.0),
    ]
    projectiles = [
        _projectile(active=True, pos=Vec2(200.0, 100.0), angle=0.0, type_id=int(ProjectileTemplateId.PISTOL)),
        _projectile(active=True, pos=Vec2(210.0, 100.0), type_id=int(ProjectileTemplateId.PLASMA_RIFLE)),
        _projectile(active=True, pos=Vec2(220.0, 100.0), type_id=0xDEAD),  # ignored, not emissive
    ]
    secondary = [
        _secondary(active=True, pos=Vec2(300.0, 100.0), type_id=int(SecondaryProjectileTypeId.DETONATION)),
    ]

    lights = collect_shadow_lights(projectiles, secondary, transients, max_lights=4)

    assert len(lights) == 4
    assert [(light.pos.x, light.pos.y) for light in lights] == [
        (100.0, 100.0),
        (110.0, 100.0),
        (200.0, 100.0),
        (210.0, 100.0),
    ]


def test_ion_lights_are_head_to_tail_omni_with_weaker_tail() -> None:
    projectiles = [
        _projectile(
            active=True,
            pos=Vec2(300.0, 100.0),
            origin=Vec2(80.0, 100.0),
            angle=0.0,
            type_id=int(ProjectileTemplateId.ION_RIFLE),
        ),
    ]

    lights = collect_shadow_lights(projectiles, [], [], max_lights=6)

    assert len(lights) == 3
    assert_float_close(lights[0].pos.x, 300.0)
    assert lights[1].pos.x < lights[0].pos.x
    assert lights[2].pos.x < lights[1].pos.x
    assert lights[0].strength > lights[1].strength > lights[2].strength
    for light in lights:
        assert_float_close(light.focus, 0.0)
        assert_float_close(light.stretch, 1.0)
        assert_float_close(light.dir_x, 0.0)
        assert_float_close(light.dir_y, 0.0)


def test_plasma_light_is_omnidirectional() -> None:
    projectiles = [
        _projectile(
            active=True,
            pos=Vec2(220.0, 100.0),
            origin=Vec2(180.0, 100.0),
            angle=1.2,
            type_id=int(ProjectileTemplateId.PLASMA_RIFLE),
        ),
    ]

    lights = collect_shadow_lights(projectiles, [], [], max_lights=6)

    assert len(lights) == 1
    assert_float_close(lights[0].focus, 0.0)
    assert_float_close(lights[0].stretch, 1.0)
    assert_float_close(lights[0].dir_x, 0.0)
    assert_float_close(lights[0].dir_y, 0.0)


def test_tick_transient_lights_decays_and_removes_expired_entries() -> None:
    lights = [
        TransientLight(pos=Vec2(50.0, 70.0), radius=60.0, strength=1.0, ttl=0.30, age=0.0),
        TransientLight(pos=Vec2(80.0, 70.0), radius=60.0, strength=0.5, ttl=0.08, age=0.0),
    ]

    step_1 = tick_transient_lights(lights, 0.04)
    assert len(step_1) == 2
    assert_float_close(step_1[0].age, 0.04)
    assert_float_close(step_1[1].age, 0.04)

    collected = collect_shadow_lights([], [], step_1, max_lights=4)
    assert len(collected) == 2
    assert_float_close(collected[0].strength, 1.0 * (1.0 - 0.04 / 0.30))
    assert_float_close(collected[1].strength, 0.5 * (1.0 - 0.04 / 0.08))

    step_2 = tick_transient_lights(step_1, 0.05)
    assert len(step_2) == 1
    assert_float_close(step_2[0].pos.x, 50.0)
    assert_float_close(step_2[0].age, 0.09)


def test_profile_auto_interval_uses_weapon_cooldown_for_all_profiles() -> None:
    for profile in EMISSIVE_PROFILES:
        assert profile.rate_weapon_id is not None
        weapon = WEAPON_BY_ID[WeaponId(profile.rate_weapon_id)]
        interval = LightingDebugView._profile_auto_interval(profile)
        assert_float_close(interval, float(weapon.shot_cooldown))


def test_profile_auto_interval_falls_back_to_profile_interval() -> None:
    profile = EmissiveProfile(name="fallback", auto_interval=0.123, rate_weapon_id=None)

    interval = LightingDebugView._profile_auto_interval(profile)

    assert_float_close(interval, 0.123)


def test_profile_light_defaults_uses_primary_or_secondary_specs() -> None:
    ion_profile = next(profile for profile in EMISSIVE_PROFILES if profile.name == "Ion Rifle")
    det_profile = next(profile for profile in EMISSIVE_PROFILES if profile.name == "Explosion")

    ion_radius, ion_strength, ion_focus, ion_stretch = _profile_light_defaults(ion_profile)
    det_radius, det_strength, det_focus, det_stretch = _profile_light_defaults(det_profile)

    assert ion_radius > 0.0
    assert ion_strength > 0.0
    assert ion_focus >= 0.0
    assert ion_stretch >= 1.0
    assert det_radius > 0.0
    assert det_strength > 0.0
    assert det_focus >= 0.0
    assert det_stretch >= 1.0


def test_build_static_occluders_produces_finite_positive_circles() -> None:
    occluders = _build_static_occluders()

    assert occluders
    assert all(occ.radius > 0.0 for occ in occluders)
    assert all(math.isfinite(float(occ.pos.x)) for occ in occluders)
    assert all(math.isfinite(float(occ.pos.y)) for occ in occluders)


def test_static_scene_collect_shadow_state_uses_static_occluders_and_emitters() -> None:
    view = LightingDebugView(ViewContext(assets_dir=Path(".") / "artifacts" / "assets"))

    view._set_static_scene_enabled(True)
    view._collect_shadow_state()

    assert view._static_scene_enabled is True
    assert len(view._last_occluders) > 0
    assert len(view._last_lights) > 0


def test_adjust_selected_tune_rt_scale_resets_shadow_rt_size() -> None:
    view = LightingDebugView(ViewContext(assets_dir=Path(".") / "artifacts" / "assets"))
    rt_param_index = 0
    for i in range(32):
        view._tune_param_index = i
        if view._selected_tune_param().key == "rt_scale":
            rt_param_index = i
            break

    view._tune_param_index = int(rt_param_index)
    assert view._selected_tune_param().key == "rt_scale"
    view._shadow_rt_size = (320, 180)
    view._shadow_accum_ready = True
    view._adjust_selected_tune(+1)

    assert view._shadow_rt_size == (0, 0)
    assert view._shadow_accum_ready is False


def test_dump_all_modes_honors_autodiag_frame_budget(mocker) -> None:
    view = LightingDebugView(ViewContext(assets_dir=Path(".") / "artifacts" / "assets"))
    view._dump_all_modes_enabled = True
    view._dump_mode_sequence = (0, 1, 2, 3)
    view._autodiag_enabled = True
    view._autodiag_total_frames = 30

    mocker.patch.object(view, "_reset_scene", side_effect=lambda: None)
    mocker.patch.object(view, "_emit_profile", side_effect=lambda: None)
    mocker.patch.object(view, "_set_tune_value", side_effect=lambda key, value, **kwargs: None)

    safety = 0
    while not view.close_requested and safety < 200:
        view._run_dump_all_modes()
        safety += 1

    assert view.close_requested is True
    assert view._dump_total_frames == 30
    assert view._dump_total_frame == 30


def test_shadow_frame_metrics_reports_higher_banding_for_step_pattern() -> None:
    smooth = [int((idx / 63.0) * 255.0) for idx in range(64)]
    stepped = []
    for idx in range(64):
        stepped.append((idx // 8) * 32)

    smooth_metrics = _shadow_frame_metrics(smooth, 8, 8)
    stepped_metrics = _shadow_frame_metrics(stepped, 8, 8)

    assert smooth_metrics is not None
    assert stepped_metrics is not None
    assert stepped_metrics.banding > smooth_metrics.banding


def test_shadow_quality_score_penalizes_banding_and_slow_shadow_pass() -> None:
    clean_metrics = _shadow_frame_metrics([int((idx / 63.0) * 255.0) for idx in range(64)], 8, 8)
    banded_metrics = _shadow_frame_metrics([(idx // 8) * 32 for idx in range(64)], 8, 8)

    assert clean_metrics is not None
    assert banded_metrics is not None

    clean_score = _shadow_quality_score(clean_metrics, shadow_ms=1.2, flicker=3.0)
    banded_score = _shadow_quality_score(banded_metrics, shadow_ms=5.2, flicker=22.0)

    assert clean_score > banded_score


def test_auto_tune_selection_score_prefers_smoother_penumbras() -> None:
    preset_a = _AutoTunePreset(
        name="a",
        ambient_darkness=0.78,
        shadow_strength=1.02,
        light_size_w=0.30,
        min_t=3.0,
        range_scale=1.55,
        directional_focus=1.15,
        directional_stretch=1.25,
        jitter_amount=1.0,
        temporal_response=1.0,
        rt_scale=0.25,
    )
    preset_b = _AutoTunePreset(
        name="b",
        ambient_darkness=0.76,
        shadow_strength=1.00,
        light_size_w=0.34,
        min_t=2.6,
        range_scale=1.52,
        directional_focus=1.12,
        directional_stretch=1.22,
        jitter_amount=0.78,
        temporal_response=1.0,
        rt_scale=0.30,
    )
    noisy = _AutoTuneResult(
        preset=preset_a,
        score=0.49,
        shadow_ms=0.25,
        mean_alpha=130.0,
        std_alpha=44.0,
        contrast=0.58,
        coverage=0.94,
        banding=0.17,
        flicker=0.1,
    )
    smooth = _AutoTuneResult(
        preset=preset_b,
        score=0.47,
        shadow_ms=0.22,
        mean_alpha=126.0,
        std_alpha=42.0,
        contrast=0.56,
        coverage=0.94,
        banding=0.12,
        flicker=0.1,
    )

    assert _auto_tune_selection_score(smooth) > _auto_tune_selection_score(noisy)
